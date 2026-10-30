#include "scm_win.hpp"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <chrono>
#include <memory>

#include "../core/render.hpp"
#include "collect.hpp"
#include "datadir_win.hpp"

namespace metasec::win {

namespace {

std::string to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

struct ScHandle {
    SC_HANDLE h = nullptr;
    ScHandle() = default;
    explicit ScHandle(SC_HANDLE x) : h(x) {}
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    ~ScHandle() {
        if (h) CloseServiceHandle(h);
    }
    explicit operator bool() const { return h != nullptr; }
};

struct LocalFreeDeleter {
    void operator()(void* p) const {
        if (p) LocalFree(p);
    }
};

std::string win32_code(DWORD e) { return e == ERROR_ACCESS_DENIED ? "ACCESS_DENIED" : "WIN32:" + std::to_string(e); }

RunState run_state_of(DWORD s) {
    switch (s) {
        case SERVICE_STOPPED: return RunState::Stopped;
        case SERVICE_START_PENDING: return RunState::StartPending;
        case SERVICE_RUNNING: return RunState::Running;
        case SERVICE_STOP_PENDING: return RunState::StopPending;
        case SERVICE_CONTINUE_PENDING: return RunState::ContinuePending;
        case SERVICE_PAUSE_PENDING: return RunState::PausePending;
        case SERVICE_PAUSED: return RunState::Paused;
        default: return RunState::Unknown;
    }
}

bool iequal(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

// Final path of an existing file/dir, "\\?\" prefix removed; "" on failure.
std::wstring final_path_of(const std::wstring& p) {
    HANDLE h = CreateFileW(p.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    wchar_t buf[2048];
    const DWORD n = GetFinalPathNameByHandleW(h, buf, static_cast<DWORD>(std::size(buf)), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(h);
    if (n == 0 || n >= std::size(buf)) return {};
    std::wstring r = buf;
    if (r.rfind(L"\\\\?\\UNC\\", 0) == 0) return r;  // network path: kept as is, never accepted by the path policy
    if (r.rfind(L"\\\\?\\", 0) == 0) r.erase(0, 4);
    return r;
}

std::string known_folder_utf8(REFKNOWNFOLDERID id) {
    PWSTR raw = nullptr;
    std::string r;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &raw)) && raw) r = to_utf8(raw);
    CoTaskMemFree(raw);
    return r;
}

// ---- side effects: reachable ONLY through real_service_change_hooks() -------------------------

ServiceChangeOutcome fail(const std::string& code, const std::string& detail) {
    ServiceChangeOutcome o;
    o.error_code = code;
    o.detail = detail;
    return o;
}

// Applies the hardening configuration; returns "" or the name of the step that failed (error in *err).
const char* configure_service(SC_HANDLE svc, DWORD* err) {
    auto step = [&](DWORD level, void* info, const char* name) -> const char* {
        if (ChangeServiceConfig2W(svc, level, info)) return nullptr;
        *err = GetLastError();
        return name;
    };
    SERVICE_DESCRIPTIONW desc{const_cast<LPWSTR>(kServiceDescription)};
    if (const char* f = step(SERVICE_CONFIG_DESCRIPTION, &desc, "description")) return f;
    SERVICE_DELAYED_AUTO_START_INFO delayed{TRUE};
    if (const char* f = step(SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed, "delayed start")) return f;
    SC_ACTION actions[3] = {{SC_ACTION_RESTART, kFailureRestartFirstMs},
                            {SC_ACTION_RESTART, kFailureRestartSecondMs},
                            {SC_ACTION_RESTART, kFailureRestartThirdMs}};
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = kFailureResetSeconds;
    fa.cActions = 3;
    fa.lpsaActions = actions;
    if (const char* f = step(SERVICE_CONFIG_FAILURE_ACTIONS, &fa, "failure actions")) return f;
    SERVICE_FAILURE_ACTIONS_FLAG flag{TRUE};
    if (const char* f = step(SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag, "failure actions flag")) return f;
    SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
    if (const char* f = step(SERVICE_CONFIG_SERVICE_SID_INFO, &sid, "service SID")) return f;
    wchar_t privileges[] = L"SeChangeNotifyPrivilege\0";  // multi-string: the literal's own NUL ends the list
    SERVICE_REQUIRED_PRIVILEGES_INFOW priv{privileges};
    if (const char* f = step(SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &priv, "required privileges")) return f;
    SERVICE_PRESHUTDOWN_INFO pre{30 * 1000};
    if (const char* f = step(SERVICE_CONFIG_PRESHUTDOWN_INFO, &pre, "preshutdown")) return f;
    return nullptr;
}

ServiceChangeOutcome install_side_effect(const std::string& exe_utf8) {
    const std::string image = build_service_image_path(exe_utf8);
    if (image.empty()) return fail("BAD_PATH", "the binary path is not acceptable");

    // The data directory first, created by this elevated process (owner: Administrators) with the protected DACL.
    const DirCheck dir = prepare_data_dir(service_data_dir(), DirMode::Service);
    if (!dir.ok) return fail("DATA_DIR", dir.error);

    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!scm) return fail(win32_code(GetLastError()), "cannot open the Service Control Manager for writing");
    const std::wstring wimage = to_wide(image);
    ScHandle svc(CreateServiceW(scm.h, kServiceNameW, to_wide(kServiceDisplayName).c_str(), SERVICE_ALL_ACCESS,
                                SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, wimage.c_str(), nullptr,
                                nullptr, nullptr, kServiceAccount, nullptr));
    if (!svc) {
        const DWORD e = GetLastError();
        return fail(win32_code(e), e == ERROR_SERVICE_EXISTS ? "the service already exists" : "CreateService failed");
    }
    DWORD err = 0;
    if (const char* failed = configure_service(svc.h, &err)) {
        // Never leave a half-configured service behind.
        const bool removed = DeleteService(svc.h) != FALSE;
        return fail(win32_code(err), std::string("could not set '") + failed + "'; " +
                                         (removed ? "the new service was removed again" : "the new service could NOT be removed, delete it with 'sc delete MetaSecAgent'"));
    }
    ServiceChangeOutcome ok;
    ok.ok = true;
    ok.detail = "created";
    return ok;
}

ServiceChangeOutcome uninstall_side_effect() {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return fail(win32_code(GetLastError()), "cannot open the Service Control Manager");
    ScHandle svc(OpenServiceW(scm.h, kServiceNameW, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!svc) {
        const DWORD e = GetLastError();
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) {
            ServiceChangeOutcome ok;
            ok.ok = true;
            ok.detail = "already absent";
            return ok;
        }
        return fail(win32_code(e), "cannot open the service");
    }
    SERVICE_STATUS_PROCESS st{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(svc.h, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&st), sizeof st, &needed))
        return fail(win32_code(GetLastError()), "cannot query the service");
    if (st.dwCurrentState != SERVICE_STOPPED) {
        SERVICE_STATUS ss{};
        if (st.dwCurrentState != SERVICE_STOP_PENDING && !ControlService(svc.h, SERVICE_CONTROL_STOP, &ss) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            return fail(win32_code(GetLastError()), "the stop request was refused");
        const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(kStopWaitSeconds) * 1000ULL;
        for (;;) {
            if (!QueryServiceStatusEx(svc.h, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&st), sizeof st, &needed))
                return fail(win32_code(GetLastError()), "cannot query the service while stopping it");
            if (st.dwCurrentState == SERVICE_STOPPED) break;
            if (GetTickCount64() >= deadline) {
                ServiceChangeOutcome o;
                o.incomplete = true;
                o.error_code = "STOP_TIMEOUT";
                o.detail = "the service did not stop within " + std::to_string(kStopWaitSeconds) + " s; it was NOT removed";
                return o;
            }
            Sleep(250);
        }
    }
    if (!DeleteService(svc.h)) {
        const DWORD e = GetLastError();
        if (e == ERROR_SERVICE_MARKED_FOR_DELETE) {
            ServiceChangeOutcome o;
            o.incomplete = true;
            o.error_code = win32_code(e);
            o.detail = "the service is marked for deletion and disappears once every handle to it is closed";
            return o;
        }
        return fail(win32_code(e), "DeleteService failed");
    }
    ServiceChangeOutcome ok;
    ok.ok = true;
    ok.detail = "stopped and deleted";
    return ok;
}

bool is_admin_sid(const std::wstring& s) {
    return s == L"S-1-5-18" || s == L"S-1-5-32-544" || s == L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
}

std::string friendly_sid(const std::wstring& s) {
    if (s == L"S-1-1-0") return "Everyone";
    if (s == L"S-1-5-11") return "Authenticated Users";
    if (s == L"S-1-5-32-545") return "Users";
    return to_utf8(s);
}

// "" if only SYSTEM/Administrators/TrustedInstaller may modify `obj`; else who can.
std::string object_exposure(const std::wstring& obj) {
    const DWORD attrs = GetFileAttributesW(obj.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return "cannot inspect " + to_utf8(obj);
    const bool is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd_raw = nullptr;
    const DWORD rc = GetNamedSecurityInfoW(obj.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd_raw);
    std::unique_ptr<void, LocalFreeDeleter> sd(sd_raw);
    if (rc != ERROR_SUCCESS) return "cannot read the access rules of " + to_utf8(obj);
    if (!dacl) return to_utf8(obj) + " has no access rules (everyone can modify it)";
    constexpr DWORD kModify = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER |
                              GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) return "cannot read the access rules of " + to_utf8(obj);
        const ACE_HEADER* hdr = static_cast<ACE_HEADER*>(raw);
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            // Callback / object ACEs: not understood, so not trusted. Deny ACEs never grant anything.
            if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) continue;
            return to_utf8(obj) + " has an access rule of a kind this check does not understand";
        }
        if (is_dir && (hdr->AceFlags & INHERIT_ONLY_ACE)) continue;  // only affects children, which are checked themselves
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if (!(ace->Mask & kModify)) continue;
        LPWSTR sid_str = nullptr;
        if (!ConvertSidToStringSidW(const_cast<PSID>(static_cast<const void*>(&ace->SidStart)), &sid_str)) continue;
        const std::wstring s = sid_str;
        LocalFree(sid_str);
        if (is_admin_sid(s)) continue;
        return friendly_sid(s) + " can modify " + to_utf8(obj);
    }
    return {};
}

}  // namespace

ServiceInfo query_service_info(DWORD* service_pid) {
    if (service_pid) *service_pid = 0;
    ServiceInfo info;
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) {
        info.query_ok = false;
        info.query_error = win32_code(GetLastError());
        return info;
    }
    ScHandle svc(OpenServiceW(scm.h, kServiceNameW, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (!svc) {
        const DWORD e = GetLastError();
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) {
            info.install = InstallState::NotInstalled;
            return info;
        }
        info.query_ok = false;
        info.query_error = win32_code(e);
        return info;
    }
    info.install = InstallState::Installed;
    SERVICE_STATUS_PROCESS st{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(svc.h, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&st), sizeof st, &needed)) {
        info.query_ok = false;
        info.query_error = win32_code(GetLastError());
        return info;
    }
    info.run = run_state_of(st.dwCurrentState);
    if (service_pid) *service_pid = st.dwProcessId;

    DWORD len = 0;
    QueryServiceConfigW(svc.h, nullptr, 0, &len);
    if (len == 0 || len > 64 * 1024) {
        info.query_ok = false;
        info.query_error = win32_code(GetLastError());
        return info;
    }
    std::vector<BYTE> buf(len);
    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
    if (!QueryServiceConfigW(svc.h, cfg, len, &len)) {
        info.query_ok = false;
        info.query_error = win32_code(GetLastError());
        return info;
    }
    bool delayed = false;
    SERVICE_DELAYED_AUTO_START_INFO d{};
    DWORD dn = 0;
    if (QueryServiceConfig2W(svc.h, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, reinterpret_cast<LPBYTE>(&d), sizeof d, &dn))
        delayed = d.fDelayedAutostart != FALSE;
    switch (cfg->dwStartType) {
        case SERVICE_AUTO_START: info.start_type = delayed ? StartType::AutoDelayed : StartType::Auto; break;
        case SERVICE_DEMAND_START: info.start_type = StartType::Manual; break;
        case SERVICE_DISABLED: info.start_type = StartType::Disabled; break;
        default: info.start_type = StartType::Unknown; break;
    }
    if (cfg->lpServiceStartName) info.account = to_utf8(cfg->lpServiceStartName);
    if (cfg->lpBinaryPathName) {
        info.binary_path = to_utf8(cfg->lpBinaryPathName);
        const std::wstring reg = final_path_of(to_wide(image_path_executable(info.binary_path)));
        const std::wstring self = to_wide(canonical_exe_path());
        if (!reg.empty() && !self.empty()) info.binary_matches_cli = iequal(reg, self);
    }
    return info;
}

std::string image_path_executable(const std::string& image_path) {
    std::string s = image_path;
    while (!s.empty() && s.front() == ' ') s.erase(s.begin());
    if (!s.empty() && s.front() == '"') {
        const std::size_t end = s.find('"', 1);
        return end == std::string::npos ? std::string() : s.substr(1, end - 1);
    }
    // Unquoted: up to the first ".exe" (case-insensitive), else the first space.
    std::string low = s;
    for (char& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const std::size_t exe = low.find(".exe");
    if (exe != std::string::npos) return s.substr(0, exe + 4);
    return s.substr(0, s.find(' '));
}

std::string canonical_exe_path() {
    wchar_t buf[2048];
    const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) return {};
    return to_utf8(final_path_of(buf));
}

std::vector<std::string> protected_install_roots() {
    std::vector<std::string> v;
    for (const std::string& r : {known_folder_utf8(FOLDERID_ProgramFiles), known_folder_utf8(FOLDERID_ProgramFilesX86),
                                 known_folder_utf8(FOLDERID_Windows)})
        if (!r.empty()) v.push_back(r);
    return v;
}

std::string binary_exposure_reason(const std::string& path, const std::vector<std::string>& roots) {
    std::wstring cur = to_wide(path);
    if (cur.empty()) return "no path";
    std::vector<std::wstring> wroots;
    for (const auto& r : roots) wroots.push_back(to_wide(r));
    for (int guard = 0; guard < 64; ++guard) {
        if (const std::string why = object_exposure(cur); !why.empty()) return why;
        for (const auto& r : wroots)
            if (iequal(cur, r)) return {};
        const std::size_t cut = cur.find_last_of(L'\\');
        if (cut == std::wstring::npos || cut < 3) break;  // reached the drive root without meeting a trusted root
        cur.resize(cut);
    }
    return "the location is not below a protected directory";
}

ServiceChangeHooks real_service_change_hooks() {
    ServiceChangeHooks h;
    h.elevated = [] { return process_elevated(); };
    h.resolve_exe_path = [] { return canonical_exe_path(); };
    h.trusted_roots = [] { return protected_install_roots(); };
    h.binary_exposure = [](const std::string& p, const std::vector<std::string>& roots) { return binary_exposure_reason(p, roots); };
    h.query_service = [] { return query_service_info(); };
    h.ask_approval = [](const std::string& prompt) { return console_approval(prompt); };
    h.actor = [] { return current_actor(); };
    h.now_utc = [] { return format_utc(std::chrono::system_clock::now()); };
    h.install = [](const std::string& exe) { return install_side_effect(exe); };
    h.uninstall = [] { return uninstall_side_effect(); };
    return h;
}

}  // namespace metasec::win
