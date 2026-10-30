#include "types.hpp"

#include <cstdio>

namespace metasec {

const char* to_string(State s) {
    switch (s) {
        case State::Enabled: return "ENABLED";
        case State::Disabled: return "DISABLED";
        case State::Good: return "GOOD";
        case State::Poor: return "POOR";
        case State::Snooze: return "SNOOZE";
        case State::NotMonitored: return "NOT_MONITORED";
        case State::Unknown: return "UNKNOWN";
        case State::NotSupported: return "NOT_SUPPORTED";
    }
    return "UNKNOWN";
}

bool is_incomplete(State s) {
    return s == State::Unknown || s == State::NotSupported || s == State::NotMonitored;
}

const char* to_string(Overall o) { return o == Overall::Observed ? "OBSERVED" : "INCOMPLETE"; }

Overall compute_overall(const std::vector<CheckResult>& checks) {
    if (checks.empty()) return Overall::Incomplete;
    for (const auto& c : checks)
        if (is_incomplete(c.state)) return Overall::Incomplete;
    return Overall::Observed;
}

int exit_code_for(Overall o) { return o == Overall::Observed ? kExitOk : kExitIncomplete; }

std::string hresult_code(std::uint32_t hr) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "HRESULT:0x%08X", static_cast<unsigned>(hr));
    return buf;
}

State classify_failure(std::uint32_t hr) {
    switch (hr) {
        case 0x80004001u:  // E_NOTIMPL
        case 0x80004002u:  // E_NOINTERFACE
        case 0x80040154u:  // REGDB_E_CLASSNOTREG
        case 0x8004100Eu:  // WBEM_E_INVALID_NAMESPACE
        case 0x80041010u:  // WBEM_E_INVALID_CLASS
        case 0x80070032u:  // HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)
        case 0x80070425u:  // HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE)
        case 0x80070426u:  // HRESULT_FROM_WIN32(ERROR_SERVICE_DOES_NOT_EXIST)
            return State::NotSupported;
        default:
            return State::Unknown;
    }
}

State wsc_health_to_state(int health) {
    switch (health) {
        case 0: return State::Good;
        case 1: return State::NotMonitored;
        case 2: return State::Poor;
        case 3: return State::Snooze;
        default: return State::Unknown;
    }
}

CheckResult make_failure(std::string check_id, std::string observed_at_utc, std::string source,
                         std::uint32_t hr) {
    CheckResult r;
    r.check_id = std::move(check_id);
    r.observed_at_utc = std::move(observed_at_utc);
    r.source = std::move(source);
    r.state = classify_failure(hr);
    r.error_code = hresult_code(hr);
    return r;
}

}  // namespace metasec
