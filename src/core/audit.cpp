#include "audit.hpp"

#include <charconv>
#include <optional>

#include "interpret.hpp"

namespace metasec {

const char* to_string(RuleResult r) {
    switch (r) {
        case RuleResult::Pass: return "PASS";
        case RuleResult::Fail: return "FAIL";
        case RuleResult::Unknown: return "UNKNOWN";
        case RuleResult::NotApplicable: return "NOT_APPLICABLE";
    }
    return "UNKNOWN";
}

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "MEDIUM";
}

const char* to_string(Obs o) {
    switch (o) {
        case Obs::Observed: return "OBSERVED";
        case Obs::Unknown: return "UNKNOWN";
        case Obs::NotSupported: return "NOT_SUPPORTED";
    }
    return "UNKNOWN";
}

const char* to_string(AvActivity a) {
    switch (a) {
        case AvActivity::Off: return "OFF";
        case AvActivity::On: return "ON";
        case AvActivity::Snoozed: return "SNOOZED";
        case AvActivity::Expired: return "EXPIRED";
        case AvActivity::Unrecognized: return "UNRECOGNIZED";
    }
    return "UNRECOGNIZED";
}

AvActivity av_activity(long long product_state) {
    if (product_state < 0 || product_state > 0xFFFFFF) return AvActivity::Unrecognized;
    switch ((product_state >> 12) & 0xF) {
        case 0: return AvActivity::Off;
        case 1: return AvActivity::On;
        case 2: return AvActivity::Snoozed;
        case 3: return AvActivity::Expired;
        default: return AvActivity::Unrecognized;
    }
}

const char* to_string(AuditOverall o) {
    switch (o) {
        case AuditOverall::NoFindings: return "NO_FINDINGS";
        case AuditOverall::Findings: return "FINDINGS";
        case AuditOverall::Incomplete: return "INCOMPLETE";
    }
    return "INCOMPLETE";
}

namespace {

const CheckResult* find_check(const AuditInput& in, const char* id) {
    for (const auto& c : in.status.checks)
        if (c.check_id == id) return &c;
    return nullptr;
}

const std::string* find_evidence(const CheckResult& c, const char* key) {
    for (const auto& [k, v] : c.evidence)
        if (k == key) return &v;
    return nullptr;
}

// Records a status check as provenance and returns it (nullptr if the engine never produced it).
const CheckResult* use(Finding& f, const AuditInput& in, const char* id) {
    f.check_ids.emplace_back(id);
    const CheckResult* c = find_check(in, id);
    if (c) {
        bool seen = false;
        for (const auto& s : f.sources) seen = seen || s == c->source;
        if (!seen) f.sources.push_back(c->source);
    }
    return c;
}

Finding make(const char* id, int version, std::string title, Severity sev, const char* remediation) {
    Finding f;
    f.rule_id = id;
    f.rule_version = version;
    f.title = std::move(title);
    f.severity = sev;
    f.remediation = remediation;
    return f;
}

// UNKNOWN with the reason (and the offending check, if any) as evidence. Returns f for chaining.
Finding& set_unknown(Finding& f, const std::string& reason, const CheckResult* c = nullptr) {
    f.result = RuleResult::Unknown;
    f.evidence.emplace_back("reason", reason);
    if (c) {
        f.evidence.emplace_back("state", to_string(c->state));
        if (!c->error_code.empty()) f.evidence.emplace_back("error_code", c->error_code);
    }
    return f;
}

const char* const kFwRemediation =
    "Turn the profile on in Windows Security > Firewall & network protection, or ask an "
    "administrator (e.g. Set-NetFirewallProfile -Profile <Domain|Private|Public> -Enabled True). "
    "If a Group Policy or another firewall manages it, fix it there.";

std::optional<long long> parse_days(const std::string& s) {
    long long v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc() || p != s.data() + s.size() || v < 0) return std::nullopt;
    return v;
}

bool is_unobserved(State s) { return s == State::Unknown || s == State::NotSupported; }

}  // namespace

Finding rule_firewall(const AuditInput& in, const char* check_id) {
    const std::string cid = check_id;
    const char* rid = cid == kIdFwDomain ? "META-FW-001" : cid == kIdFwPrivate ? "META-FW-002" : "META-FW-003";
    const char* profile = cid == kIdFwDomain ? "Domain" : cid == kIdFwPrivate ? "Private" : "Public";
    Finding f = make(rid, kRuleVersionFirewall,
                     std::string("Windows Firewall is enabled for the ") + profile + " profile",
                     Severity::High, kFwRemediation);
    const CheckResult* c = use(f, in, check_id);
    if (!c) return set_unknown(f, "check was not produced");
    f.evidence.emplace_back("profile", profile);
    if (c->state == State::Enabled) {
        f.result = RuleResult::Pass;
        f.evidence.emplace_back("state", "ENABLED");
    } else if (c->state == State::Disabled) {
        f.result = RuleResult::Fail;
        f.evidence.emplace_back("state", "DISABLED");
    } else {
        set_unknown(f, "firewall profile state could not be observed", c);
    }
    f.evidence.emplace_back("note", "profile on/off only; effective rules are not audited");
    return f;
}

Finding rule_wsc_health(const AuditInput& in) {
    Finding f = make("META-AV-001", kRuleVersionWscHealth,
                     "Windows Security Center reports antivirus health GOOD", Severity::High,
                     "Open Windows Security > Virus & threat protection and resolve the warning: "
                     "turn the antivirus back on, update its signatures, or end the snooze.");
    const CheckResult* c = use(f, in, kIdWsc);
    if (!c) return set_unknown(f, "check was not produced");
    switch (c->state) {
        case State::Good:
            f.result = RuleResult::Pass;
            f.evidence.emplace_back("state", "GOOD");
            break;
        case State::Poor:
        case State::Snooze:
            f.result = RuleResult::Fail;
            f.evidence.emplace_back("state", to_string(c->state));
            break;
        default:
            // NOT_MONITORED means Windows does not track AV health: not a pass, not proof of absence.
            set_unknown(f, c->state == State::NotMonitored
                               ? "Windows Security Center does not monitor antivirus health"
                               : "antivirus health could not be observed",
                        c);
            break;
    }
    f.evidence.emplace_back("note", "aggregate of all registered antivirus products, not Defender-specific");
    return f;
}

Finding rule_active_av(const AuditInput& in) {
    Finding f = make("META-AV-002", kRuleVersionActiveAv, "At least one antivirus engine is active",
                     Severity::High,
                     "Enable real-time protection in Windows Security (Virus & threat protection), "
                     "or install and activate an antivirus product. Ask an administrator if a policy "
                     "prevents it.");
    const CheckResult* av = use(f, in, kIdDefenderAv);
    const CheckResult* rt = use(f, in, kIdDefenderRt);
    const CheckResult* wsc = use(f, in, kIdWsc);
    const AvProductsObservation& ap = in.av_products;
    f.check_ids.emplace_back("av_products");
    f.sources.push_back(ap.source);

    const State av_s = av ? av->state : State::Unknown;
    const State rt_s = rt ? rt->state : State::Unknown;
    const State wsc_s = wsc ? wsc->state : State::Unknown;
    const std::string* mode = av ? find_evidence(*av, "am_running_mode") : nullptr;

    f.evidence.emplace_back("defender_antivirus", to_string(av_s));
    f.evidence.emplace_back("defender_realtime", to_string(rt_s));
    if (mode) f.evidence.emplace_back("am_running_mode", *mode);
    f.evidence.emplace_back("registered_products_source", to_string(ap.obs));
    if (!ap.error_code.empty()) f.evidence.emplace_back("registered_products_error", ap.error_code);

    // A. Defender itself is the active engine (direct evidence).
    if (av_s == State::Enabled && rt_s == State::Enabled) {
        f.result = RuleResult::Pass;
        f.evidence.emplace_back("active_engine", "Microsoft Defender");
        return f;
    }

    if (ap.obs == Obs::Observed) {
        f.evidence.emplace_back("registered_products", std::to_string(ap.products.size()));
        int on = 0;
        int unrecognized = 0;
        std::string on_names;
        for (const auto& p : ap.products) {
            const AvActivity a = av_activity(p.product_state);
            if (a == AvActivity::On) {
                ++on;
                if (!on_names.empty()) on_names += "; ";
                on_names += p.name;
            } else if (a == AvActivity::Unrecognized) {
                ++unrecognized;
            }
        }
        // B. A registered product is ON (vendor self-reported through Security Center).
        if (on > 0) {
            f.result = RuleResult::Pass;
            f.evidence.emplace_back("active_engine", on_names);
            f.evidence.emplace_back("note", "registration is self-reported by the product via Security Center");
            return f;
        }
        if (unrecognized > 0)
            return set_unknown(f, "a registered antivirus product has an unrecognized productState");
        // Every registered product (possibly none) is recognized and not ON. Without a usable
        // Defender reading we cannot rule out that Defender is the active engine.
        const bool no_defender_provider = av_s == State::NotSupported && rt_s == State::NotSupported;
        if (!no_defender_provider && (is_unobserved(av_s) || is_unobserved(rt_s)))
            return set_unknown(f, "Defender state could not be observed and no registered product is on");
        f.result = RuleResult::Fail;
        f.evidence.emplace_back("detail", "Defender is not active and no registered antivirus product is on");
        return f;
    }

    // C. Registered products could not be listed (Server SKU or a failed query): only direct
    // evidence that Defender is the primary engine and off, or Security Center confirming
    // that nothing is healthy, may produce a FAIL.
    const bool defender_primary_off = rt_s == State::Disabled && mode && *mode == "Normal";
    const bool wsc_confirms_off = rt_s == State::Disabled && (wsc_s == State::Poor || wsc_s == State::Snooze);
    if (defender_primary_off || wsc_confirms_off) {
        f.result = RuleResult::Fail;
        f.evidence.emplace_back("detail", defender_primary_off
                                              ? "Defender is the primary engine and real-time protection is off"
                                              : "Defender real-time protection is off and Security Center reports no healthy antivirus");
        return f;
    }
    return set_unknown(f, av_s == State::Passive || rt_s == State::Passive
                              ? "Defender is passive and the registered antivirus list is unavailable"
                              : "antivirus engines could not be determined");
}

Finding rule_defender_realtime(const AuditInput& in) {
    Finding f = make("META-AV-003", kRuleVersionDefenderRealtime,
                     "Defender real-time protection is on when Defender is the primary engine",
                     Severity::High,
                     "Turn on Real-time protection in Windows Security > Virus & threat protection > "
                     "Manage settings, or ask an administrator if a policy blocks it.");
    const CheckResult* av = use(f, in, kIdDefenderAv);
    const CheckResult* rt = use(f, in, kIdDefenderRt);
    if (!av || !rt) return set_unknown(f, "check was not produced");
    if (rt->state == State::NotSupported && av->state == State::NotSupported) {
        f.result = RuleResult::NotApplicable;
        f.evidence.emplace_back("reason", "Microsoft Defender provider is not present on this machine");
        f.evidence.emplace_back("error_code", rt->error_code);
        return f;
    }
    if (is_unobserved(rt->state) || is_unobserved(av->state))
        return set_unknown(f, "Defender real-time protection could not be observed", is_unobserved(rt->state) ? rt : av);
    const std::string* mode = find_evidence(*av, "am_running_mode");
    if (!mode) return set_unknown(f, "Defender running mode is not known, so primary status cannot be determined");
    f.evidence.emplace_back("am_running_mode", *mode);
    if (*mode != "Normal") {
        f.result = RuleResult::NotApplicable;
        f.evidence.emplace_back("reason", "Defender is not the primary engine; see META-AV-002");
        return f;
    }
    f.evidence.emplace_back("realtime_protection", to_string(rt->state));
    f.result = rt->state == State::Enabled ? RuleResult::Pass : RuleResult::Fail;
    return f;
}

Finding rule_signature_age(const AuditInput& in) {
    Finding f = make("META-AV-004", kRuleVersionSignatureAge,
                     "Defender signatures are at most " + std::to_string(kSignatureMaxAgeDays) + " days old",
                     Severity::Medium,
                     "Update protection intelligence: Windows Security > Virus & threat protection > "
                     "Protection updates > Check for updates, and make sure Windows Update can reach "
                     "Microsoft.");
    const CheckResult* av = use(f, in, kIdDefenderAv);
    if (!av) return set_unknown(f, "check was not produced");
    f.evidence.emplace_back("threshold_days", std::to_string(kSignatureMaxAgeDays));
    if (av->state == State::NotSupported) {
        f.result = RuleResult::NotApplicable;
        f.evidence.emplace_back("reason", "no reliable signature-age source on this machine");
        return f;
    }
    if (av->state == State::Unknown) return set_unknown(f, "Defender state could not be observed", av);
    const std::string* mode = find_evidence(*av, "am_running_mode");
    if (!mode) return set_unknown(f, "Defender running mode is not known, so signature age is not trusted");
    f.evidence.emplace_back("am_running_mode", *mode);
    if (*mode != "Normal") {
        f.result = RuleResult::NotApplicable;
        f.evidence.emplace_back("reason", "Defender is not the primary engine; its signature age says nothing about the active engine");
        return f;
    }
    const std::string* age = find_evidence(*av, "signature_age_days");
    const auto days = age ? parse_days(*age) : std::nullopt;
    if (!days) return set_unknown(f, "Defender did not report a usable signature age");
    f.evidence.emplace_back("signature_age_days", *age);
    if (const std::string* v = find_evidence(*av, "signature_version"))
        f.evidence.emplace_back("signature_version", *v);
    f.result = *days <= kSignatureMaxAgeDays ? RuleResult::Pass : RuleResult::Fail;
    return f;
}

AuditReport run_audit(const AuditInput& in) {
    AuditReport r;
    r.hostname = in.status.hostname;
    r.observed_at_utc = in.status.observed_at_utc;
    r.platform = in.status.platform;
    r.findings.push_back(rule_firewall(in, kIdFwDomain));
    r.findings.push_back(rule_firewall(in, kIdFwPrivate));
    r.findings.push_back(rule_firewall(in, kIdFwPublic));
    r.findings.push_back(rule_wsc_health(in));
    r.findings.push_back(rule_active_av(in));
    r.findings.push_back(rule_defender_realtime(in));
    r.findings.push_back(rule_signature_age(in));
    return r;
}

AuditSummary summarize(const AuditReport& r) {
    AuditSummary s;
    for (const auto& f : r.findings) {
        switch (f.result) {
            case RuleResult::Pass: ++s.pass; break;
            case RuleResult::Fail: ++s.fail; break;
            case RuleResult::Unknown: ++s.unknown; break;
            case RuleResult::NotApplicable: ++s.not_applicable; break;
        }
    }
    return s;
}

AuditOverall audit_overall(const AuditReport& r) {
    if (r.findings.empty()) return AuditOverall::Incomplete;
    const AuditSummary s = summarize(r);
    if (s.fail > 0) return AuditOverall::Findings;
    return s.unknown > 0 ? AuditOverall::Incomplete : AuditOverall::NoFindings;
}

int audit_exit_code(AuditOverall o) {
    switch (o) {
        case AuditOverall::Findings: return kExitViolation;
        case AuditOverall::Incomplete: return kExitIncomplete;
        case AuditOverall::NoFindings: return kExitOk;
    }
    return kExitError;
}

}  // namespace metasec
