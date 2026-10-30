#pragma once
// Pure interpretation of raw provider output into CheckResults. The Windows layer only
// fetches raw values; every decision about what they mean lives here so it can be tested
// with fakes on any host.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "types.hpp"

namespace metasec {

inline constexpr const char* kIdFwDomain = "firewall.domain";
inline constexpr const char* kIdFwPrivate = "firewall.private";
inline constexpr const char* kIdFwPublic = "firewall.public";
inline constexpr const char* kIdWsc = "antivirus.windows_security_center";
inline constexpr const char* kIdDefenderAv = "antivirus.defender.antivirus";
inline constexpr const char* kIdDefenderRt = "antivirus.defender.realtime_protection";

// Windows reports 65535 for "signature age not available" when Defender is not running.
inline constexpr long long kSignatureAgeUnavailable = 65535;

// hr < 0 (FAILED) => failure result; otherwise `enabled` decides ENABLED/DISABLED.
CheckResult interpret_firewall_profile(const std::string& check_id, const std::string& now_utc,
                                       std::int32_t hr, bool enabled);

// hr < 0 => failure result; otherwise health (WSC_SECURITY_PROVIDER_HEALTH) is mapped.
CheckResult interpret_wsc(const std::string& now_utc, std::int32_t hr, int health);

struct DefenderRaw {
    std::optional<bool> antivirus_enabled;   // AntivirusEnabled
    std::optional<bool> realtime_enabled;    // RealTimeProtectionEnabled
    std::optional<bool> service_enabled;     // AMServiceEnabled
    std::optional<bool> tamper_protected;    // IsTamperProtected
    std::optional<std::string> running_mode; // AMRunningMode: Normal / Passive / SxS Passive Mode / Not running ...
    std::optional<long long> signature_age_days;
    std::optional<std::string> signature_version;
    std::optional<std::string> product_version;
};

// Two checks (antivirus, realtime_protection). Decision order:
//  0. AMRunningMode present but not an allowlisted value (including "" and "normal"):
//     UNKNOWN with error_code UNRECOGNIZED_RUNNING_MODE:<sanitized>; flags are not used.
//  1. AMRunningMode present and not "Normal": Defender is not the primary engine.
//     - "Not running" while WSC reports GOOD  -> PASSIVE (another AV is healthy)
//     - "Not running" otherwise               -> DISABLED
//     - any other mode (Passive, SxS, EDR block) -> PASSIVE
//     The raw AntivirusEnabled flag can be TRUE in passive mode, so it is never trusted there.
//  2. Otherwise the raw flags decide; a missing flag is UNKNOWN, never a positive state.
std::vector<CheckResult> interpret_defender(const DefenderRaw& raw, State wsc_state,
                                            const std::string& now_utc);

// Both Defender checks as failed (same cause).
std::vector<CheckResult> defender_failure(const std::string& now_utc, State state,
                                          const std::string& error_code);

}  // namespace metasec
