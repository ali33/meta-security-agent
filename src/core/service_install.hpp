#pragma once
// MVP-4: `service install` / `service uninstall`. Pure decision flow with injected hooks, the same
// pattern as scan (MVP-3): the Windows layer supplies observations and the ONE side effect
// (create / delete the service) as hooks, so tests can prove with fakes that the side effect is
// never called without Administrator rights AND typed approval.
//
// Order is fixed and is the security contract:
//   elevated? (no => REFUSED, nothing prompted)
//   -> install only: binary path policy (refused => nothing prompted)
//   -> service exists? (install: already installed => REFUSED; uninstall: absent => no-op, exit 0)
//   -> --dry-run stops here (prints the plan)
//   -> typed approval (evaluate_approval(in, phrase))
//   -> re-check elevation, path and existence (the human may have taken a while)
//   -> the single side-effect hook.
//
// Exit codes: done / ok 0, refused 4, failure 2, incomplete 3.
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "service_model.hpp"

namespace metasec {

enum class ServiceChange { Install, Uninstall };

// ---- Binary path policy (pure) ---------------------------------------------------------------
// A service runs with its account's rights, so the registered binary must be in a place a
// non-administrator cannot write; otherwise "install" would hand SYSTEM-class code execution to
// any user who can replace the file. Allowed: inside one of `trusted_roots` (%ProgramFiles%,
// %ProgramFiles(x86)%, %SystemRoot%). Anything else is refused with a reason.
struct BinaryPathCheck {
    bool allowed = false;
    std::string code;     // PATH_OK | PATH_UNKNOWN | PATH_NOT_ABSOLUTE | PATH_ODD_CHARACTERS | PATH_NOT_EXE |
                          // PATH_NOT_IN_PROTECTED_LOCATION | PATH_WRITABLE_BY_NON_ADMINS
    std::string message;  // human text
};
BinaryPathCheck evaluate_service_binary_path(std::string_view path, const std::vector<std::string>& trusted_roots);

// The ImagePath handed to the SCM: the path QUOTED, then " service run --scm". Empty when the path
// would not pass evaluate_service_binary_path's character rules (never builds an unquoted path).
std::string build_service_image_path(std::string_view exe_path);

// ---- Flow ------------------------------------------------------------------------------------
enum class ServiceChangeStatus {
    DryRunWouldProceed,       // exit 0: every pre-check passes; a real run would still ask for approval
    Done,                     // exit 0: the service was created / deleted
    NoOpNotInstalled,         // exit 0: uninstall, but the service does not exist (nothing to do)
    RefusedNotElevated,       // exit 4
    RefusedBadBinaryPath,     // exit 4 (install)
    RefusedAlreadyInstalled,  // exit 4 (install)
    RefusedNotApproved,       // exit 4
    Failed,                   // exit 2: the side effect reported an error
    Incomplete,               // exit 3: could not observe the SCM, or the change is only partly done
};
const char* to_string(ServiceChangeStatus s);
int service_change_exit_code(ServiceChangeStatus s);

// What the side-effect hook reports.
struct ServiceChangeOutcome {
    bool ok = false;          // fully done
    bool incomplete = false;  // partly done (e.g. stop timed out, delete pending reboot): exit 3
    std::string error_code;   // e.g. "WIN32:5" (set when !ok)
    std::string detail;       // short human text (sanitized by the renderer)
};

struct ServiceChangeOptions {
    ServiceChange change = ServiceChange::Install;
    bool dry_run = false;
    bool json = false;
};

struct ServiceChangeHooks {
    std::function<bool()> elevated;
    std::function<std::string()> resolve_exe_path;            // canonical absolute path of this meta-sec.exe ("" = unknown)
    std::function<std::vector<std::string>()> trusted_roots;  // protected directories (install)
    // Optional second look at the binary's location (install): "" when only administrators/SYSTEM/TrustedInstaller
    // can write the file and every directory down to its trusted root, otherwise the reason it is exposed
    // (e.g. C:\Windows\Temp lies inside %SystemRoot% but any user can write there).
    std::function<std::string(const std::string& path, const std::vector<std::string>& roots)> binary_exposure;
    std::function<ServiceInfo()> query_service;               // SCM observation (query_ok / install state)
    std::function<ApprovalInput(const std::string& prompt)> ask_approval;  // MUST NOT prompt unless stdin is a console
    std::function<std::string()> actor;
    std::function<std::string()> now_utc;
    // THE side effects. Never called unless every gate above passed.
    std::function<ServiceChangeOutcome(const std::string& exe_path)> install;
    std::function<ServiceChangeOutcome()> uninstall;
};

struct ServiceChangeReport {
    ServiceChange change = ServiceChange::Install;
    bool dry_run = false;
    ServiceChangeStatus status = ServiceChangeStatus::RefusedNotElevated;
    std::string observed_at_utc;
    std::string finished_at_utc;
    bool elevated = false;
    std::string binary_path;  // as resolved (install)
    BinaryPathCheck path;     // install only (allowed=false, code empty for uninstall)
    bool service_query_ok = true;
    bool service_exists = false;
    bool approval_asked = false;
    ApprovalDecision approval;
    std::string actor;
    std::string approved_at_utc;
    bool change_attempted = false;
    ServiceChangeOutcome outcome;
};

ServiceChangeReport run_service_change(const ServiceChangeOptions& opt, const ServiceChangeHooks& hooks);

// One line of JSON ("command":"service install" | "service uninstall", schema_version 1) / text.
std::string render_service_change_json(const ServiceChangeReport& r, const std::string& version);
std::string render_service_change_text(const ServiceChangeReport& r, const std::string& version);

}  // namespace metasec
