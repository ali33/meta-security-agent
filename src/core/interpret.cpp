#include "interpret.hpp"

namespace metasec {

namespace {

const char* const kFwSource = "INetFwPolicy2";
const char* const kWscSource = "WscGetSecurityProviderHealth";
const char* const kDefSource = "WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpComputerStatus";

CheckResult base(const char* id, const std::string& now, const char* source) {
    CheckResult c;
    c.check_id = id;
    c.observed_at_utc = now;
    c.source = source;
    return c;
}

const char* tf(bool b) { return b ? "true" : "false"; }

CheckResult from_flag(const char* id, const std::string& now, const std::optional<bool>& flag,
                      const char* prop) {
    CheckResult c = base(id, now, kDefSource);
    if (!flag) {
        c.state = State::Unknown;
        c.error_code = std::string("PROPERTY_UNAVAILABLE:") + prop;
    } else {
        c.state = *flag ? State::Enabled : State::Disabled;
    }
    return c;
}

}  // namespace

CheckResult interpret_firewall_profile(const std::string& check_id, const std::string& now_utc,
                                       std::int32_t hr, bool enabled) {
    if (hr < 0)
        return make_failure(check_id, now_utc, kFwSource, static_cast<std::uint32_t>(hr));
    CheckResult c = base(check_id.c_str(), now_utc, kFwSource);
    c.state = enabled ? State::Enabled : State::Disabled;
    return c;
}

CheckResult interpret_wsc(const std::string& now_utc, std::int32_t hr, int health) {
    if (hr < 0) return make_failure(kIdWsc, now_utc, kWscSource, static_cast<std::uint32_t>(hr));
    CheckResult c = base(kIdWsc, now_utc, kWscSource);
    c.state = wsc_health_to_state(health);
    return c;
}

std::vector<CheckResult> defender_failure(const std::string& now_utc, State state,
                                          const std::string& error_code) {
    return {make_failure_code(kIdDefenderAv, now_utc, kDefSource, state, error_code),
            make_failure_code(kIdDefenderRt, now_utc, kDefSource, state, error_code)};
}

std::vector<CheckResult> interpret_defender(const DefenderRaw& raw, State wsc_state,
                                            const std::string& now_utc) {
    CheckResult av = from_flag(kIdDefenderAv, now_utc, raw.antivirus_enabled, "AntivirusEnabled");
    CheckResult rt = from_flag(kIdDefenderRt, now_utc, raw.realtime_enabled,
                               "RealTimeProtectionEnabled");

    if (raw.running_mode) {
        av.evidence.emplace_back("am_running_mode", *raw.running_mode);
        if (*raw.running_mode != "Normal") {
            const bool not_running = *raw.running_mode == "Not running";
            State s = State::Passive;
            const char* reason = "defender is not the primary engine";
            if (not_running) {
                if (wsc_state == State::Good) {
                    reason = "defender not running; Windows Security Center reports another healthy AV";
                } else {
                    s = State::Disabled;
                    reason = "defender not running and no healthy AV confirmed by Windows Security Center";
                }
            }
            for (CheckResult* c : {&av, &rt}) {
                c->state = s;
                c->error_code.clear();
                c->evidence.emplace_back("reason", reason);
            }
        }
    }

    if (raw.service_enabled) av.evidence.emplace_back("am_service_enabled", tf(*raw.service_enabled));
    if (raw.signature_age_days && *raw.signature_age_days != kSignatureAgeUnavailable)
        av.evidence.emplace_back("signature_age_days", std::to_string(*raw.signature_age_days));
    if (raw.signature_version) av.evidence.emplace_back("signature_version", *raw.signature_version);
    if (raw.product_version) av.evidence.emplace_back("am_product_version", *raw.product_version);
    if (raw.tamper_protected) rt.evidence.emplace_back("tamper_protected", tf(*raw.tamper_protected));
    return {std::move(av), std::move(rt)};
}

}  // namespace metasec
