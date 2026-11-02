#pragma once
// Scan command (MVP-3): the only side effect in the product is one Defender quick scan, and only
// after (1) a pure eligibility gate and (2) explicit human approval typed on a real console.
// Everything here is pure: the Windows layer supplies observations and the actual Start call as
// injected hooks, so tests can prove "Start is never called without approval" with fakes.
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "audit.hpp"
#include "types.hpp"

namespace metasec {

// Exit code 4: the scan was refused (not applicable here, or not approved). Distinct from 2 (error).
constexpr int kExitRefused = 4;

// Upper bound for waiting on the scan; there is no way to cancel it, so after this we only report.
inline constexpr int kScanWaitSeconds = 1800;
// The exact line the human must type (case-sensitive, nothing else on the line).
inline constexpr const char* kScanConfirmPhrase = "START QUICK SCAN";

// ---- Defender observation used by the gate and the post-scan check -------------------------

// QuickScanStartTime / QuickScanEndTime from MSFT_MpComputerStatus as UTC epoch seconds.
struct ScanTimes {
    std::optional<long long> quick_start;
    std::optional<long long> quick_end;
};

struct DefenderScanObservation {
    Obs obs = Obs::Unknown;                   // Observed / Unknown (call failed) / NotSupported (no namespace)
    std::string error_code;                   // set when obs != Observed
    std::optional<std::string> running_mode;  // AMRunningMode
    ScanTimes times;
};

// CIM datetime "yyyymmddHHMMSS.mmmmmm+UUU" (UUU = minutes east of UTC) -> UTC epoch seconds.
// Anything malformed, wildcarded or out of range -> nullopt.
std::optional<long long> parse_cim_datetime(std::string_view s);
std::string format_epoch_utc(long long epoch_seconds);

// ---- Gate ----------------------------------------------------------------------------------

struct ScanGate {
    bool allowed = false;
    std::string code;     // DEFENDER_NORMAL | DEFENDER_UNAVAILABLE | DEFENDER_NOT_SUPPORTED | MODE_* ...
    std::string message;  // human text: why, and what to do instead
    std::vector<std::string> protecting_av;  // names of registered AVs reported ON (sanitized)
    std::string running_mode;                // as observed ("" if unknown)
};

// Fail closed: allowed only when the Defender namespace was observed AND AMRunningMode is exactly
// "Normal". Passive / not running / unknown / unobservable => refused with a reason.
ScanGate evaluate_scan_gate(const DefenderScanObservation& def, const AvProductsObservation& av);

// ---- Approval ------------------------------------------------------------------------------

enum class ReadStatus { Ok, Eof, Error, Interrupted };

// What the Windows layer observed when it tried to ask the human.
struct ApprovalInput {
    bool input_is_console = false;   // stdin is a real console input handle
    bool output_is_console = false;  // the prompt (stderr) is on a real console, so a human can see it
    ReadStatus read = ReadStatus::Eof;
    std::string line;  // one line typed by the human, line terminator included or not
};

struct ApprovalDecision {
    bool approved = false;
    std::string reason;  // APPROVED | NOT_A_CONSOLE | NO_VISIBLE_PROMPT | EOF | READ_ERROR | INTERRUPTED | WRONG_CONFIRMATION
};

ApprovalDecision evaluate_approval(const ApprovalInput& in);
// Same state machine for any action: `phrase` is the exact line the human must type (case-sensitive,
// one line terminator required). An empty `phrase` never approves. evaluate_approval(in) is this
// with kScanConfirmPhrase. Reused by `service install` / `service uninstall`.
ApprovalDecision evaluate_approval(const ApprovalInput& in, std::string_view phrase);

// Text shown before asking. `actor` is the Windows account that will be recorded.
std::string approval_prompt_text(const std::string& actor, const std::string& running_mode, bool elevated);

// ---- Start call and its interpretation -----------------------------------------------------

enum class WaitEnd { Finished, TimedOut, Interrupted, NoCallResult };  // NoCallResult: accepted, but nothing to wait on

struct StartResult {
    std::int32_t exec_hr = 0;                // HRESULT of the ExecMethod call itself
    std::int32_t status_hr = 0;              // HRESULT the finished call reports (when waited on)
    std::optional<long long> return_value;   // method ReturnValue, if the method returns one
    WaitEnd wait = WaitEnd::Finished;
};

enum class ScanStatus {
    DryRunWouldProceed,    // exit 0: gate passes; real run would still ask for approval
    RefusedNotApplicable,  // exit 4: gate refused
    RefusedNotApproved,    // exit 4: no valid approval
    AccessDenied,          // exit 2: Windows denied the Start call (needs elevation / policy)
    StartFailed,           // exit 2: Start returned an error
    Completed,             // exit 0: call finished and a new scan is visible in the Defender timestamps
    StartedNotCompleted,   // exit 3: new scan visible, but we stopped waiting (timeout / Ctrl+C)
    NotConfirmed,          // exit 3: call did not fail, but no new scan is visible
};
const char* to_string(ScanStatus s);
int scan_exit_code(ScanStatus s);

// Pure: decide the outcome from the Start result and the before/after timestamps.
// `after` is nullopt when Defender could not be re-read.
ScanStatus interpret_scan_outcome(const StartResult& r, const ScanTimes& before,
                                  const std::optional<ScanTimes>& after, long long not_before);
// True when `after` shows a quick scan that began after `before` (strictly later start time) AND
// not earlier than `not_before` (epoch seconds when we called Start, minus kScanClockSlackSeconds),
// so an old scan can never be taken for ours.
inline constexpr long long kScanClockSlackSeconds = 2;  // WMI timestamps are truncated to seconds
bool new_scan_visible(const ScanTimes& before, const std::optional<ScanTimes>& after, long long not_before);

// ---- Orchestration -------------------------------------------------------------------------

struct ScanOptions {
    bool json = false;
    bool dry_run = false;
};

struct ScanHooks {
    std::function<DefenderScanObservation()> observe_defender;
    std::function<AvProductsObservation()> observe_av;
    // Shows `prompt` and reads one line. MUST NOT prompt (or read) when stdin is not a console.
    std::function<ApprovalInput(const std::string& prompt)> ask_approval;
    std::function<std::string()> actor;  // Windows account running this process
    std::function<bool()> elevated;      // process token is elevated
    // The ONLY side effect. Never called unless the gate and the approval both passed.
    std::function<StartResult(int timeout_seconds)> start_quick_scan;
    std::function<std::string()> now_utc;
    std::function<long long()> now_epoch;  // UTC epoch seconds
};

struct ScanReport {
    bool dry_run = false;
    ScanStatus status = ScanStatus::RefusedNotApplicable;
    std::string observed_at_utc;
    ScanGate gate;
    bool elevated = false;
    // approval
    bool approval_asked = false;
    ApprovalDecision approval;
    std::string actor;
    std::string approved_at_utc;
    // start
    bool start_attempted = false;
    StartResult start;
    ScanTimes before;
    std::optional<ScanTimes> after;
    bool new_scan_confirmed = false;
    std::string finished_at_utc;
};

// Runs the whole flow. Order is fixed and is the security contract:
//   observe -> gate -> (dry-run stops here) -> approval -> observe again + gate again -> Start.
ScanReport run_scan(const ScanOptions& opt, const ScanHooks& hooks);

std::string render_scan_json(const ScanReport& r, const std::string& version);
std::string render_scan_text(const ScanReport& r, const std::string& version);

}  // namespace metasec
