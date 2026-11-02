#pragma once
// Pure security-core types. No Windows headers: everything here is unit-testable on any host.
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace metasec {

enum class State {
    Enabled,
    Disabled,
    Good,
    Poor,
    Snooze,
    NotMonitored,
    Passive,       // observed, but another AV is primary (Defender passive / not running)
    Unknown,       // the call failed or returned something we cannot interpret
    NotSupported,  // the API / provider does not exist on this machine
};

const char* to_string(State s);
// Inverse of to_string(State); exact, case-sensitive; nullopt for anything else.
std::optional<State> state_from_string(std::string_view s);

// States that mean "we did not actually observe the setting".
bool is_incomplete(State s);

// Per-check reading of a state. Observation != approval: DISABLED is ATTENTION, not fine.
enum class Posture { Ok, Attention, Unknown, NotApplicable };
const char* to_string(Posture p);
Posture posture_of(State s);

struct CheckResult {
    std::string check_id;
    std::string observed_at_utc;  // ISO 8601, e.g. 2026-10-30T12:34:56Z
    State state = State::Unknown;
    std::vector<std::pair<std::string, std::string>> evidence;  // ordered key/value pairs
    std::string source;
    std::string error_code;  // empty when the call succeeded
};

struct PlatformInfo {
    std::string os;       // "windows"
    std::string version;  // e.g. "10.0.26200"
    std::string kind;     // "client" | "server" | "unknown"
};

struct StatusReport {
    std::string hostname;
    std::string observed_at_utc;
    PlatformInfo platform;
    std::vector<CheckResult> checks;
};

// Incomplete: some check could not be observed (exit 3).
// ObservedWithIssues: everything observed, but at least one check is ATTENTION (exit 0:
//   `status` observes, only `audit` (MVP-1) returns exit 1).
enum class Overall { Observed, ObservedWithIssues, Incomplete };
const char* to_string(Overall o);

// Ids of checks whose posture is ATTENTION.
std::vector<std::string> attention_ids(const std::vector<CheckResult>& checks);

// Observed* only if there is at least one check and every check yielded a real observation.
// This is a statement about the observation, never a protection verdict.
Overall compute_overall(const std::vector<CheckResult>& checks);

// Exit codes (docs/HANDOFF.md section G).
constexpr int kExitOk = 0;
constexpr int kExitViolation = 1;  // reserved for audit (MVP-1)
constexpr int kExitError = 2;
constexpr int kExitIncomplete = 3;

int exit_code_for(Overall o);

// "HRESULT:0x80070005"
std::string hresult_code(std::uint32_t hr);

// A failed call must never become a positive state. Maps an HRESULT to
// NotSupported (API/provider absent) or Unknown (anything else).
State classify_failure(std::uint32_t hr);

// WSC_SECURITY_PROVIDER_HEALTH numeric value -> State (0=GOOD 1=NOTMONITORED 2=POOR 3=SNOOZE).
State wsc_health_to_state(int health);

// Failure with an explicit non-HRESULT code (e.g. "TIMEOUT"). `state` must be Unknown or
// NotSupported; anything else is coerced to Unknown.
CheckResult make_failure_code(std::string check_id, std::string observed_at_utc, std::string source,
                              State state, std::string error_code);

// Builds a result for a failed call. State is never positive.
CheckResult make_failure(std::string check_id, std::string observed_at_utc, std::string source,
                         std::uint32_t hr);

}  // namespace metasec
