#include "datadir_win.hpp"

#include <windows.h>

#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>

#include <cstring>
#include <memory>
#include <system_error>
#include <vector>

#include "../core/service_model.hpp"

namespace metasec::win {

namespace {

constexpr const wchar_t* kSidSystem = L"S-1-5-18";
constexpr const wchar_t* kSidAdministrators = L"S-1-5-32-544";
// FILE_GENERIC_READ|WRITE|EXECUTE + DELETE: the standard "Modify" mask (no WRITE_DAC, no WRITE_OWNER).
constexpr const wchar_t* kModifyMask = L"0x1301bf";

struct LocalFreeDeleter {
    void operator()(void* p) const {
        if (p) LocalFree(p);
    }
};
using LocalMem = std::unique_ptr<void, LocalFreeDeleter>;

struct HandleDeleter {
    void operator()(void* h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using Handle = std::unique_ptr<void, HandleDeleter>;
struct FindCloser {
    void operator()(void* h) const {
        if (h && h != INVALID_HANDLE_VALUE) FindClose(h);
    }
};
using FindHandle = std::unique_ptr<void, FindCloser>;

std::string code_of(DWORD e) { return "WIN32:" + std::to_string(e); }

std::filesystem::path known_folder(REFKNOWNFOLDERID id, const wchar_t* leaf) {
    PWSTR raw = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &raw);
    std::filesystem::path p;
    if (SUCCEEDED(hr) && raw) p = std::filesystem::path(raw) / leaf;
    CoTaskMemFree(raw);
    return p;
}

std::wstring sid_to_string(PSID sid) {
    LPWSTR s = nullptr;
    if (!sid || !ConvertSidToStringSidW(sid, &s)) return {};
    std::wstring r = s;
    LocalFree(s);
    return r;
}

bool same_path(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

std::vector<std::wstring> allowed_sids(DirMode mode, const std::wstring& extra) {
    std::vector<std::wstring> v{kSidSystem, kSidAdministrators};
    if (mode == DirMode::Service) v.push_back(service_sid_string(kServiceNameW));
    else v.push_back(current_user_sid_string());
    if (!extra.empty()) v.push_back(extra);
    return v;
}

// Service mode: everything already inside the directory must be what the service itself would have made.
// "" when fine, else why not. Entries must be plain files (no sub-directory, no reparse point, no extra hard
// link -- a hard link would let another path alias a store file) owned by a trusted account.
std::string children_problem(const std::filesystem::path& dir, const std::vector<std::wstring>& trusted) {
    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW((dir / L"*").c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        return e == ERROR_FILE_NOT_FOUND ? std::string() : "cannot list the data directory (" + code_of(e) + ")";
    }
    FindHandle guard(find);
    do {
        const std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) return "the data directory contains a reparse point";
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return "the data directory contains an unexpected sub-directory";
        HANDLE raw = CreateFileW((dir / name).c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (raw == INVALID_HANDLE_VALUE) return "cannot inspect an entry of the data directory (" + code_of(GetLastError()) + ")";
        Handle h(raw);
        BY_HANDLE_FILE_INFORMATION bi{};
        if (!GetFileInformationByHandle(raw, &bi)) return "cannot inspect an entry of the data directory";
        if (bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) return "the data directory contains a reparse point";
        if (bi.nNumberOfLinks > 1) return "the data directory contains a hard-linked file";
        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR sd_raw = nullptr;
        const DWORD rc = GetSecurityInfo(raw, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd_raw);
        LocalMem sd(sd_raw);
        if (rc != ERROR_SUCCESS) return "cannot read the owner of an entry of the data directory";
        const std::wstring o = sid_to_string(owner);
        bool ok = false;
        for (const auto& t : trusted)
            if (!t.empty() && t == o) ok = true;
        if (!ok) return "the data directory contains a file owned by another account";
    } while (FindNextFileW(find, &fd));
    return {};
}

}  // namespace

std::filesystem::path service_data_dir() { return known_folder(FOLDERID_ProgramData, L"MetaSecAgent"); }

std::filesystem::path dev_data_dir() { return known_folder(FOLDERID_LocalAppData, L"MetaSecAgent-dev"); }

std::wstring service_sid_string(const std::wstring& service_name) {
    std::wstring upper = service_name;
    if (!upper.empty()) CharUpperBuffW(upper.data(), static_cast<DWORD>(upper.size()));
    UCHAR hash[20]{};
    const NTSTATUS st = BCryptHash(BCRYPT_SHA1_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(upper.data()),
                                   static_cast<ULONG>(upper.size() * sizeof(wchar_t)), hash, sizeof hash);
    if (st < 0) return {};
    std::wstring s = L"S-1-5-80";
    for (int i = 0; i < 5; ++i) {
        DWORD d = 0;
        std::memcpy(&d, hash + i * 4, 4);  // little-endian DWORDs, as the SCM derives them
        s += L"-" + std::to_wstring(d);
    }
    return s;
}

std::wstring current_user_sid_string() {
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return {};
    Handle token(t);
    DWORD len = 0;
    GetTokenInformation(t, TokenUser, nullptr, 0, &len);
    if (len == 0) return {};
    std::vector<BYTE> buf(len);
    if (!GetTokenInformation(t, TokenUser, buf.data(), len, &len)) return {};
    return sid_to_string(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid);
}

std::wstring data_dir_sddl(DirMode mode, const std::wstring& extra) {
    const std::wstring extra_ace = extra.empty() ? std::wstring() : L"(A;OICI;FA;;;" + extra + L")";
    if (mode == DirMode::Service) {
        const std::wstring svc = service_sid_string(kServiceNameW);
        if (svc.empty()) return {};
        return std::wstring(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;") + kModifyMask + L";;;" + svc + L")" + extra_ace;
    }
    const std::wstring user = current_user_sid_string();
    if (user.empty()) return {};
    return L"D:P(A;OICI;FA;;;" + user + L")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + extra_ace;
}

DirCheck prepare_data_dir(const std::filesystem::path& dir, DirMode mode, const std::wstring& extra_full_control_sid) {
    DirCheck r;
    if (dir.empty() || !dir.is_absolute() || dir.native().rfind(L"\\\\", 0) == 0) {  // UNC, \.\ and \?\ forms are never used
        r.error = "data directory path is empty, not absolute, or a UNC/device path";
        return r;
    }
    const std::wstring sddl = data_dir_sddl(mode, extra_full_control_sid);
    if (sddl.empty()) {
        r.error = "could not build the access rules for the data directory";
        return r;
    }
    PSECURITY_DESCRIPTOR psd_raw = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd_raw, nullptr)) {
        r.error = "access rules rejected (" + code_of(GetLastError()) + ")";
        return r;
    }
    LocalMem psd(psd_raw);
    BOOL present = FALSE, defaulted = FALSE;
    PACL new_dacl = nullptr;
    if (!GetSecurityDescriptorDacl(psd_raw, &present, &new_dacl, &defaulted) || !present || !new_dacl) {
        r.error = "access rules have no DACL";
        return r;
    }

    // Create when missing, with the protected DACL from the first instant (no window with inherited rules).
    std::error_code ec;
    if (mode == DirMode::UserOnly) std::filesystem::create_directories(dir.parent_path(), ec);
    SECURITY_ATTRIBUTES sa{sizeof sa, psd_raw, FALSE};
    if (CreateDirectoryW(dir.c_str(), &sa)) {
        r.created = true;
    } else if (GetLastError() != ERROR_ALREADY_EXISTS) {
        r.error = "cannot create the data directory (" + code_of(GetLastError()) + ")";
        return r;
    }

    // Open the directory itself (not what a reparse point points to) and judge it through the handle.
    constexpr DWORD kShare = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    constexpr DWORD kFlags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    HANDLE raw = CreateFileW(dir.c_str(), READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES, kShare, nullptr, OPEN_EXISTING, kFlags, nullptr);
    if (raw == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED)
        raw = CreateFileW(dir.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, kShare, nullptr, OPEN_EXISTING, kFlags, nullptr);
    if (raw == INVALID_HANDLE_VALUE) {
        r.error = "cannot open the data directory (" + code_of(GetLastError()) + ")";
        return r;
    }
    Handle h(raw);

    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(raw, &info)) {
        r.error = "cannot inspect the data directory (" + code_of(GetLastError()) + ")";
        return r;
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        r.error = "the data directory is a reparse point (junction or symbolic link); refusing to use it";
        return r;
    }
    if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        r.error = "the data directory path is not a directory";
        return r;
    }
    if (mode == DirMode::Service) {
        // A junction anywhere above the leaf would redirect the store elsewhere: compare the real path.
        wchar_t fin[1024];
        const DWORD n = GetFinalPathNameByHandleW(raw, fin, static_cast<DWORD>(std::size(fin)), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        wchar_t lng[1024];
        const DWORD m = GetLongPathNameW(dir.c_str(), lng, static_cast<DWORD>(std::size(lng)));
        if (n == 0 || n >= std::size(fin) || m == 0 || m >= std::size(lng)) {
            r.error = "cannot resolve the real path of the data directory";
            return r;
        }
        std::wstring real = fin;
        if (real.rfind(L"\\\\?\\", 0) == 0) real.erase(0, 4);
        if (!same_path(real, lng)) {
            r.error = "the data directory path passes through a reparse point; refusing to use it";
            return r;
        }
    }

    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd_raw = nullptr;
    DWORD rc = GetSecurityInfo(raw, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl,
                               nullptr, &sd_raw);
    LocalMem sd(sd_raw);
    if (rc != ERROR_SUCCESS) {
        r.error = "cannot read the data directory's access rules (" + code_of(rc) + ")";
        return r;
    }
    // Service mode: a pre-existing directory must belong to SYSTEM, Administrators or the service SID -- never to
    // the account the process happens to run as (that would accept a directory pre-created by that account's
    // other programs). Only a directory created a moment ago by this very call may be owned by the creator.
    // Foreground mode keeps current-user semantics.
    std::vector<std::wstring> trusted_owners = allowed_sids(mode, extra_full_control_sid);
    if (mode == DirMode::UserOnly || r.created) trusted_owners.push_back(current_user_sid_string());
    const std::wstring owner_s = sid_to_string(owner);
    bool owner_ok = false;
    for (const auto& s : trusted_owners)
        if (!s.empty() && s == owner_s) owner_ok = true;
    if (!owner_ok) {
        r.error = "the data directory is owned by an untrusted account; refusing to use it";
        return r;
    }

    if (mode == DirMode::Service) {
        // Files the service itself wrote are owned by the running account (LocalService), so that one is accepted here.
        std::vector<std::wstring> child_owners = allowed_sids(mode, extra_full_control_sid);
        child_owners.push_back(current_user_sid_string());
        const std::string bad = children_problem(dir, child_owners);
        if (!bad.empty()) {
            r.error = bad + "; refusing to use it";
            return r;
        }
    }

    // Development directory chosen by the user that already holds files: do not rewrite its rules.
    if (mode == DirMode::UserOnly && !r.created) {
        std::error_code e2;
        if (std::filesystem::directory_iterator(dir, e2) != std::filesystem::directory_iterator() && !e2) {
            r.ok = true;
            return r;
        }
    }

    // Re-apply the protected DACL; a process that does not own the directory may lack WRITE_DAC,
    // in which case the existing rules must already be exactly right (verified below).
    rc = SetSecurityInfo(raw, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                         new_dacl, nullptr);
    if (rc == ERROR_SUCCESS) r.dacl_reapplied = true;
    else if (rc != ERROR_ACCESS_DENIED) {
        r.error = "cannot apply the data directory's access rules (" + code_of(rc) + ")";
        return r;
    }

    // Verify what is in force now: DACL present, protected, and allows no one but the expected accounts.
    PACL cur = nullptr;
    PSECURITY_DESCRIPTOR sd2_raw = nullptr;
    rc = GetSecurityInfo(raw, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &cur, nullptr, &sd2_raw);
    LocalMem sd2(sd2_raw);
    if (rc != ERROR_SUCCESS || !cur) {
        r.error = "cannot verify the data directory's access rules";
        return r;
    }
    SECURITY_DESCRIPTOR_CONTROL ctrl = 0;
    DWORD rev = 0;
    if (!GetSecurityDescriptorControl(sd2_raw, &ctrl, &rev) || !(ctrl & SE_DACL_PROTECTED)) {
        r.error = "the data directory inherits access rules from its parent; refusing to use it";
        return r;
    }
    const std::vector<std::wstring> allowed = allowed_sids(mode, extra_full_control_sid);
    for (DWORD i = 0; i < cur->AceCount; ++i) {
        void* ace_raw = nullptr;
        if (!GetAce(cur, i, &ace_raw)) {
            r.error = "cannot read the data directory's access rules";
            return r;
        }
        const ACE_HEADER* hdr = static_cast<ACE_HEADER*>(ace_raw);
        if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) {
            r.error = "the data directory has an unexpected kind of access rule; refusing to use it";
            return r;
        }
        const std::wstring s = sid_to_string(&static_cast<ACCESS_ALLOWED_ACE*>(ace_raw)->SidStart);
        bool known = false;
        for (const auto& a : allowed)
            if (!a.empty() && a == s) known = true;
        if (!known) {
            r.error = "the data directory grants access to an account other than SYSTEM, Administrators and the service; refusing to use it";
            return r;
        }
    }
    r.ok = true;
    return r;
}

}  // namespace metasec::win
