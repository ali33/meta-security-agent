#pragma once
// MVP-4 (Windows half): the Service Control Manager side. Reading (`service status`) needs no
// Administrator rights; writing (create/delete the service) lives ONLY behind real_service_change_hooks(),
// which core/service_install's gate calls after elevation, path policy, existence check and typed approval.
//
// Service configuration (all in scm_win.cpp constants):
//   account               NT AUTHORITY\LocalService  (not LocalSystem: least privilege)
//   service SID type      UNRESTRICTED  (NT SERVICE\MetaSecAgent appears in the token; used in the data-dir ACL)
//   required privileges   SeChangeNotifyPrivilege only
//   start                 AUTO_START + delayed
//   failure actions       restart after 60 s, restart after 60 s, restart after 5 min; reset period 1 day;
//                         also applied to non-crash failures (service stops with an error exit code)
//   ImagePath             "<this exe>" service run --scm     (quoted)
// UNMEASURED (no Administrator here): whether LocalService can read Defender (WMI ROOT\Microsoft\Windows\
// Defender) and the firewall policy (WMI/COM). If a check then shows UNKNOWN / access denied in
// `service status` (service_overall INCOMPLETE), the fallback is running the service as LocalSystem:
//   sc config MetaSecAgent obj= LocalSystem      (the data-dir ACL uses the service SID, so it keeps working)
#include <windows.h>

#include <string>
#include <vector>

#include "../core/service_install.hpp"
#include "../core/service_model.hpp"

namespace metasec::win {

// SCM view of the service. Works as a standard user (SC_MANAGER_CONNECT + SERVICE_QUERY_*).
// `service_pid` (optional) receives the process id the SCM reports (0 when not running).
ServiceInfo query_service_info(DWORD* service_pid = nullptr);

// Canonical (final, long, no \\?\ prefix) path of this meta-sec.exe as UTF-8; "" when unknown.
std::string canonical_exe_path();

// %ProgramFiles%, %ProgramFiles(x86)%, %SystemRoot% via SHGetKnownFolderPath (UTF-8).
std::vector<std::string> protected_install_roots();

// "" when `path` and every directory above it up to (and including) one of `roots` grants write /
// delete / change-permissions only to SYSTEM, Administrators and TrustedInstaller; otherwise why not.
// Unreadable security info counts as exposed (fail closed).
std::string binary_exposure_reason(const std::string& path, const std::vector<std::string>& roots);

// ImagePath as registered by the SCM -> the executable's path (handles the quoted form).
std::string image_path_executable(const std::string& image_path);

// All real hooks for `service install` / `uninstall` (elevation, console approval, SCM side effects).
ServiceChangeHooks real_service_change_hooks();

// Service account / configuration constants (also used by tests).
inline constexpr const wchar_t* kServiceAccount = L"NT AUTHORITY\\LocalService";
inline constexpr const wchar_t* kServiceDescription =
    L"META Security Agent: read-only background observer of firewall and antivirus status. Stores small change events "
    L"locally and answers local status queries. Changes no setting.";
inline constexpr DWORD kFailureResetSeconds = 24 * 60 * 60;
inline constexpr DWORD kFailureRestartFirstMs = 60 * 1000;
inline constexpr DWORD kFailureRestartSecondMs = 60 * 1000;
inline constexpr DWORD kFailureRestartThirdMs = 5 * 60 * 1000;
inline constexpr DWORD kStopWaitSeconds = 30;

}  // namespace metasec::win
