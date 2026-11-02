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

    // Read-only, share-read; no FILE_FLAG_DELETE_ON_CLOSE, no write access ever requested.
    Handle file(CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr));
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
