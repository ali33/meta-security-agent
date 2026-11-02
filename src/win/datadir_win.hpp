#pragma once
// MVP-4 (Windows half): where the service keeps its event store, and the access rules on it.
//
// Service data directory  %ProgramData%\MetaSecAgent   (SHGetKnownFolderPath, never environment variables)
//   Protected DACL, nothing inherited from ProgramData (whose parent grants Users create/read):
//     D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;<service SID>)
//   SYSTEM and Administrators full control, the service's own SID (NT SERVICE\MetaSecAgent) Modify,
//   inheritable to files and sub-directories. Ordinary users have NO access: the CLI reads events
//   only through the named pipe. Verify with:  icacls "%ProgramData%\MetaSecAgent"
// Foreground development directory  %LOCALAPPDATA%\MetaSecAgent-dev  (or --data-dir): current user,
//   SYSTEM and Administrators only:  D:P(A;OICI;FA;;;<user SID>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
#include <filesystem>
#include <string>

namespace metasec::win {

// Must equal metasec::kServiceName (core/service_model.hpp); checked by tests/test_service_win.cpp.
inline constexpr const wchar_t* kServiceNameW = L"MetaSecAgent";

enum class DirMode {
    Service,   // %ProgramData%\MetaSecAgent rules (SYSTEM, Administrators, service SID)
    UserOnly,  // development / --data-dir: current user (+ SYSTEM, Administrators)
};

// "" when the known folder cannot be resolved.
std::filesystem::path service_data_dir();
std::filesystem::path dev_data_dir();

// Service SID of `service_name`, computed like the SCM does (SHA-1 of the upper-cased name):
// S-1-5-80-a-b-c-d-e. Works without the service being installed. "" on failure.
std::wstring service_sid_string(const std::wstring& service_name);

// SID of the account this process runs as ("" on failure).
std::wstring current_user_sid_string();

// The exact SDDL applied to the directory ("" if a SID could not be resolved). `extra_full_control_sid` (empty in
// production) adds one more full-control account: used by tests that are neither SYSTEM, Administrators nor the service.
std::wstring data_dir_sddl(DirMode mode, const std::wstring& extra_full_control_sid = {});

struct DirCheck {
    bool ok = false;
    bool created = false;
    bool dacl_reapplied = false;  // false: only verified (the process may not be allowed to change the DACL)
    std::string error;            // short, no secrets; set when !ok
};

// Creates the directory if missing (with the protected DACL from the start), then on every call:
// refuses a reparse point (junction/symlink) as the directory or (Service mode) anywhere on its path,
// refuses an owner other than SYSTEM / Administrators / the service / this process's account,
// re-applies the protected DACL, and verifies that no one else is granted access.
// Fail closed: !ok means the store MUST NOT be opened there.
DirCheck prepare_data_dir(const std::filesystem::path& dir, DirMode mode, const std::wstring& extra_full_control_sid = {});

}  // namespace metasec::win
