#pragma once
// MVP-4: pure model of `meta-sec service status` / `service events`. The Windows half fills in
// ServiceInfo (from the Service Control Manager) and IpcSnapshot / IpcEventsData (from the pipe);
// everything below turns those observations into a verdict, an exit code and text/JSON, so the
// decision logic is unit-tested with fakes.
//
// Exit codes (docs/CLI.md): a service that is not installed, or installed but stopped, is a valid
// OBSERVATION (exit 0) -- the product is standalone-first. Exit 3 means "could not observe
// completely": SCM query failed (access denied...), the service is running but its pipe cannot be
// read, or it is changing state. Never exit 2 for an observation; 2 is for bad arguments/engine
// failure. A refused install/uninstall uses kExitRefused (4), shared with `scan`.
#include <optional>
#include <string>
#include <vector>

#include "ipc_proto.hpp"
#include "observer.hpp"
#include "scan.hpp"
#include "types.hpp"

namespace metasec {

inline constexpr const char* kServiceName = "MetaSecAgent";
inline constexpr const char* kServiceDisplayName = "META Security Agent";
inline constexpr const char* kDefaultPipeName = "MetaSecAgent";  // \\.\pipe\MetaSecAgent
inline constexpr std::size_t kPipeNameMaxLen = 64;
inline constexpr std::size_t kDataDirMaxLen = 260;

// Exact phrases the human types to approve a service change (see evaluate_approval in scan.hpp).
inline constexpr const char* kServiceInstallPhrase = "INSTALL SERVICE";
inline constexpr const char* kServiceUninstallPhrase = "UNINSTALL SERVICE";
// Prompt shown before asking. `install` selects install vs uninstall wording.
std::string service_approval_prompt_text(bool install, const std::string& actor, bool elevated);
// Same, also showing what will be registered / removed: the full ImagePath and the account (empty = omitted).
std::string service_approval_prompt_text(bool install, const std::string& actor, bool elevated, const std::string& image_path,
                                         const std::string& account);

enum class InstallState { NotInstalled, Installed };
enum class RunState { Stopped, StartPending, Running, StopPending, ContinuePending, PausePending, Paused, Unknown };
enum class StartType { Auto, AutoDelayed, Manual, Disabled, Unknown };
const char* to_string(InstallState s);  // "NOT_INSTALLED" | "INSTALLED"
const char* to_string(RunState s);      // "STOPPED" "START_PENDING" "RUNNING" ... "UNKNOWN"
const char* to_string(StartType s);     // "AUTO" "AUTO_DELAYED" "MANUAL" "DISABLED" "UNKNOWN"

// What the Service Control Manager said.
struct ServiceInfo {
    bool query_ok = true;       // false: the SCM could not be queried (access denied, RPC error...)
    std::string query_error;    // e.g. "ACCESS_DENIED" or "WIN32:5"; set when query_ok == false
    InstallState install = InstallState::NotInstalled;
    RunState run = RunState::Unknown;
    StartType start_type = StartType::Unknown;
    std::string account;        // e.g. "LocalSystem", "NT SERVICE\\MetaSecAgent"
    std::string binary_path;    // registered binary path, as the SCM reports it
    std::optional<bool> binary_matches_cli;  // registered binary is the same file as this meta-sec.exe
};

enum class IpcReach { NotTried, Ok, Unreachable, AccessDenied, InvalidReply };
const char* to_string(IpcReach r);  // "NOT_TRIED" "OK" "UNREACHABLE" "ACCESS_DENIED" "INVALID_REPLY"

// What the pipe said for STATUS.
struct IpcSnapshot {
    IpcReach reach = IpcReach::NotTried;
    std::string reason;                    // why not Ok (short, from the Windows half or parse_response)
    std::optional<ObserverStatus> status;  // set when reach == Ok
};

enum class ServiceVerdict {
    NotInstalled,       // OBSERVED, exit 0
    Stopped,            // OBSERVED, exit 0
    Running,            // OBSERVED, exit 0
    RunningWithIssues,  // OBSERVED_WITH_ISSUES, exit 0 (store/snapshot errors reported by the service)
    Pending,            // INCOMPLETE, exit 3 (starting / stopping)
    IpcUnavailable,     // INCOMPLETE, exit 3 (running, but the pipe cannot be read)
    QueryFailed,        // INCOMPLETE, exit 3 (SCM query failed)
    UnexpectedState,    // INCOMPLETE, exit 3 (paused / unknown)
};
const char* to_string(ServiceVerdict v);  // "NOT_INSTALLED" "STOPPED" "RUNNING" "RUNNING_WITH_ISSUES" ...

struct ServiceStatusReport {
    std::string observed_at_utc;
    ServiceInfo service;
    IpcSnapshot ipc;
    ServiceVerdict verdict = ServiceVerdict::QueryFailed;
    Overall overall = Overall::Incomplete;  // OBSERVED / OBSERVED_WITH_ISSUES / INCOMPLETE
    int exit_code = kExitIncomplete;
    std::string message;                    // one plain sentence, sanitized
};

ServiceStatusReport build_service_status_report(const std::string& observed_at_utc, const ServiceInfo& svc,
                                                const IpcSnapshot& ipc);

// One line of JSON ("command":"service status", schema_version 1) / human text. Strings are
// sanitized; the binary path is shown only for the service itself and with the user-profile
// segment redacted ("C:\Users\<user>\..."), truncated to kDataDirMaxLen.
std::string render_service_status_json(const ServiceStatusReport& r, const std::string& version);
std::string render_service_status_text(const ServiceStatusReport& r, const std::string& version);

// --- service events (read through the pipe) ---------------------------------------------------
struct ServiceEventsReport {
    std::string observed_at_utc;
    IpcReach reach = IpcReach::NotTried;
    std::string reason;                  // why the events could not be read
    std::optional<IpcEventsData> data;   // set when reach == Ok
    int limit = kIpcDefaultEvents;       // what the user asked for
};
// 0 when read; 3 when the service could not be reached or replied with garbage.
int service_events_exit_code(const ServiceEventsReport& r);
std::string render_service_events_json(const ServiceEventsReport& r, const std::string& version);
std::string render_service_events_text(const ServiceEventsReport& r, const std::string& version);

// Terminal-safe text: ASCII controls, C1 controls (U+0080..9F, e.g. the CSI U+009B) and bidirectional
// override/isolate/mark characters (U+202A..E, U+2066..9, U+200E/F, U+061C) become '?', so untrusted text
// can neither drive the terminal nor visually reorder a report line.
std::string strip_unsafe_display(std::string_view s);

// Pure helper: user-profile segment redacted, control characters removed, length capped.
std::string redact_binary_path(const std::string& path);

}  // namespace metasec
