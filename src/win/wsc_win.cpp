#include <windows.h>
#include <objbase.h>

#include <wscapi.h>

#include "../core/interpret.hpp"
#include "collect.hpp"

namespace metasec::win {

namespace {

using WscHealthFn = HRESULT(WINAPI*)(DWORD, PWSC_SECURITY_PROVIDER_HEALTH);

// wscapi.dll is absent on Windows Server SKUs, so it is loaded at run time from System32
// only. A static import would stop the whole executable from starting there.
HRESULT query_wsc_health(WSC_SECURITY_PROVIDER_HEALTH* health) {
    HMODULE mod = LoadLibraryExW(L"wscapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!mod) return HRESULT_FROM_WIN32(GetLastError());
    HRESULT hr = HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    const auto fn = reinterpret_cast<WscHealthFn>(
        reinterpret_cast<void*>(GetProcAddress(mod, "WscGetSecurityProviderHealth")));
    if (fn) hr = fn(WSC_SECURITY_PROVIDER_ANTIVIRUS, health);
    FreeLibrary(mod);
    return hr;
}

}  // namespace

// Windows Security Center aggregate antivirus health. This is the health of whichever
// AV product(s) registered with WSC, NOT a Defender-specific verdict (see defender_win.cpp).
std::vector<CheckResult> wsc_checks(const std::string& now_utc) {
    WSC_SECURITY_PROVIDER_HEALTH health = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
    const HRESULT hr = query_wsc_health(&health);
    return {interpret_wsc(now_utc, hr, static_cast<int>(health))};
}

}  // namespace metasec::win
