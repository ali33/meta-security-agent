#include <windows.h>
#include <objbase.h>

#include <string>

#include "collect.hpp"

namespace metasec::win {

namespace {

std::string to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n, nullptr,
                        nullptr);
    return s;
}

}  // namespace

ComApartment::ComApartment() : hr_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)), owns_(false) {
    // S_OK and S_FALSE both require a matching CoUninitialize; RPC_E_CHANGED_MODE does not.
    owns_ = hr_ >= 0;
    if (owns_) {
        // Needed by WMI. RPC_E_TOO_LATE just means security was already set: not an error here.
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    }
}

ComApartment::~ComApartment() {
    if (owns_) CoUninitialize();
}

std::string host_name() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(buf, &len)) return "UNKNOWN";
    return to_utf8(std::wstring(buf, len));
}

PlatformInfo platform_info() {
    PlatformInfo p;
    p.os = "windows";
    p.version = "unknown";
    p.kind = "unknown";
    // RtlGetVersion is not subject to the manifest-based version lie of GetVersionEx.
    using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOEXW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return p;
    const auto fn =
        reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));
    if (!fn) return p;
    OSVERSIONINFOEXW vi{};
    vi.dwOSVersionInfoSize = sizeof vi;
    if (fn(&vi) != 0) return p;
    p.version = std::to_string(vi.dwMajorVersion) + "." + std::to_string(vi.dwMinorVersion) + "." +
                std::to_string(vi.dwBuildNumber);
    p.kind = vi.wProductType == VER_NT_WORKSTATION ? "client" : "server";
    return p;
}

}  // namespace metasec::win
