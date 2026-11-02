#include "policy_file_win.hpp"

#include <windows.h>

#include <vector>

#include "../core/policy.hpp"

namespace metasec::win {

namespace {

class Handle {
public:
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() {
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return h_; }
    bool valid() const { return h_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE h_;
};

PolicyFileRead fail(std::string why) {
    PolicyFileRead r;
    r.error = std::move(why);
    return r;
}

bool starts_with(const std::wstring& s, const wchar_t* prefix) { return s.rfind(prefix, 0) == 0; }

}  // namespace

PolicyFileRead read_policy_file(const std::string& utf8_path) {
    if (utf8_path.empty()) return fail("policy file path is empty");
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_path.data(),
                                      static_cast<int>(utf8_path.size()), nullptr, 0);
    if (n <= 0) return fail("policy file path is not valid UTF-8");
    std::wstring wide(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_path.data(), static_cast<int>(utf8_path.size()),
                        wide.data(), n);

    // BEFORE opening anything: the drive the path lands on must be local. A mapped network drive would
    // otherwise be contacted (SMB, NTLM) by CreateFile before any check on the opened handle could run.
    std::wstring full(MAX_PATH * 2, L'\0');
    const DWORD flen = GetFullPathNameW(wide.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
    if (flen == 0 || flen >= full.size()) return fail("policy file path cannot be resolved");
    full.resize(flen);
    if (full.size() < 3 || !((full[0] >= L'A' && full[0] <= L'Z') || (full[0] >= L'a' && full[0] <= L'z')) ||
        full[1] != L':' || full[2] != L'\\')
        return fail("policy file is not on a local drive; copy it to a local disk");
    const std::wstring root = full.substr(0, 3);
    const UINT dt = GetDriveTypeW(root.c_str());
    if (dt != DRIVE_FIXED && dt != DRIVE_REMOVABLE && dt != DRIVE_CDROM && dt != DRIVE_RAMDISK)
        return fail("policy file is not on a local drive; copy it to a local disk");

    // No component of the path may be a reparse point (symlink, junction, subst-to-share target...): the
    // final-component flag below does not stop a linked DIRECTORY in the middle of the path from leading to a
    // share. Each prefix is inspected without being opened (GetFileAttributesW does not follow the last part).
    for (std::size_t pos = 3; pos <= full.size(); ++pos) {
        if (pos != full.size() && full[pos] != L'\\') continue;
        const std::wstring prefix = full.substr(0, pos);
        const DWORD attr = GetFileAttributesW(prefix.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            const DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return fail("policy file not found");
            return fail("policy file path cannot be inspected (Win32 error " + std::to_string(e) + ")");
        }
        if (attr & FILE_ATTRIBUTE_REPARSE_POINT)
            return fail("policy file path contains a link (symlink or junction); use a real local path");
    }

    // Read-only, share-read; no write access ever requested. Reparse points are opened as themselves
    // (not followed) and refused below, so a link to a share, and cloud placeholders that would be
    // downloaded on read, never get read.
    Handle file(CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file.valid()) {
        const DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return fail("policy file not found");
        if (e == ERROR_ACCESS_DENIED) return fail("policy file cannot be opened: access denied");
        return fail("policy file cannot be opened (Win32 error " + std::to_string(e) + ")");
    }
    if (GetFileType(file.get()) != FILE_TYPE_DISK) return fail("policy path is not a regular file");

    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.get(), &info)) return fail("policy file cannot be inspected");
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return fail("policy path is a directory, not a file");
    if (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN |
                                 FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS))
        return fail("policy file is a link or an online-only (cloud) file; copy a real file to a local disk");

    // Network share (also reached through a mapped drive or a link): refused, so reading the policy can
    // never cause network traffic. If the final path cannot be determined, refuse (fail closed).
    std::wstring final_path(1024, L'\0');
    const DWORD len = GetFinalPathNameByHandleW(file.get(), final_path.data(), static_cast<DWORD>(final_path.size()),
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (len == 0 || len >= final_path.size()) return fail("policy file location cannot be determined");
    final_path.resize(len);
    // Only "\\?\X:\..." (a drive letter) is accepted; "\\?\UNC\server\share" and anything else is refused.
    const bool local_drive = starts_with(final_path, L"\\\\?\\") && final_path.size() >= 7 &&
                             ((final_path[4] >= L'A' && final_path[4] <= L'Z') || (final_path[4] >= L'a' && final_path[4] <= L'z')) &&
                             final_path[5] == L':' && final_path[6] == L'\\';
    if (!local_drive) return fail("policy file is not on a local drive (network share?); copy it to a local disk");

    const unsigned long long size = (static_cast<unsigned long long>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    if (size > kMaxPolicyBytes) return fail("policy file is larger than " + std::to_string(kMaxPolicyBytes) + " bytes");

    std::string content;
    content.reserve(static_cast<std::size_t>(size));
    std::vector<char> buf(4096);
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(file.get(), buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr))
            return fail("policy file cannot be read");
        if (got == 0) break;
        content.append(buf.data(), got);
        // The file may have grown after the size check: the bound applies to what was actually read.
        if (content.size() > kMaxPolicyBytes) return fail("policy file is larger than " + std::to_string(kMaxPolicyBytes) + " bytes");
    }
    PolicyFileRead r;
    r.ok = true;
    r.content = std::move(content);
    return r;
}

}  // namespace metasec::win
