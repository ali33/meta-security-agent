// Defender-specific state via the supported WMI provider
// ROOT\Microsoft\Windows\Defender : MSFT_MpComputerStatus (read-only query, COM, no PowerShell).
// This file only fetches raw values; interpretation lives in core/interpret.cpp.
#include <windows.h>
#include <objbase.h>

#include <Wbemidl.h>
#include <comdef.h>
#include <wrl/client.h>

#include <optional>
#include <string>

#include "../core/interpret.hpp"
#include "collect.hpp"

namespace metasec::win {

using Microsoft::WRL::ComPtr;

namespace {

struct Variant {
    VARIANT v;
    Variant() { VariantInit(&v); }
    ~Variant() { VariantClear(&v); }
    Variant(const Variant&) = delete;
    Variant& operator=(const Variant&) = delete;
};

std::string narrow(const wchar_t* w) {
    if (!w) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<std::size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

std::optional<bool> get_bool(IWbemClassObject* o, const wchar_t* name) {
    Variant var;
    if (FAILED(o->Get(name, 0, &var.v, nullptr, nullptr)) || var.v.vt != VT_BOOL) return std::nullopt;
    return var.v.boolVal != VARIANT_FALSE;
}

std::optional<long long> get_int(IWbemClassObject* o, const wchar_t* name) {
    Variant var;
    if (FAILED(o->Get(name, 0, &var.v, nullptr, nullptr))) return std::nullopt;
    switch (var.v.vt) {
        case VT_I4: return var.v.lVal;
        case VT_UI4: return var.v.ulVal;
        case VT_I2: return var.v.iVal;
        case VT_UI2: return var.v.uiVal;
        case VT_UI1: return var.v.bVal;
        default: return std::nullopt;
    }
}

std::optional<std::string> get_string(IWbemClassObject* o, const wchar_t* name) {
    Variant var;
    if (FAILED(o->Get(name, 0, &var.v, nullptr, nullptr)) || var.v.vt != VT_BSTR || !var.v.bstrVal)
        return std::nullopt;
    return narrow(var.v.bstrVal);
}

std::vector<CheckResult> fail_hr(const std::string& now_utc, HRESULT hr) {
    const auto code = static_cast<std::uint32_t>(hr);
    return defender_failure(now_utc, classify_failure(code), hresult_code(code));
}

}  // namespace

std::vector<CheckResult> defender_checks(const std::string& now_utc, State wsc_state) {
    ComPtr<IWbemLocator> locator;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&locator));
    if (FAILED(hr)) return fail_hr(now_utc, hr);

    ComPtr<IWbemServices> services;
    _bstr_t ns(L"ROOT\\Microsoft\\Windows\\Defender");
    // USE_MAX_WAIT bounds the connect to at most two minutes instead of blocking indefinitely.
    hr = locator->ConnectServer(ns, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                                nullptr, nullptr, &services);
    if (FAILED(hr)) return fail_hr(now_utc, hr);

    hr = CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) return fail_hr(now_utc, hr);

    ComPtr<IEnumWbemClassObject> en;
    hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT * FROM MSFT_MpComputerStatus"),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
    if (FAILED(hr)) return fail_hr(now_utc, hr);

    ComPtr<IWbemClassObject> obj;
    ULONG returned = 0;
    hr = en->Next(10000 /* ms */, 1, &obj, &returned);
    if (FAILED(hr)) return fail_hr(now_utc, hr);
    if (hr == WBEM_S_TIMEDOUT) return defender_failure(now_utc, State::Unknown, "TIMEOUT");
    if (returned == 0 || !obj) return defender_failure(now_utc, State::Unknown, "NO_INSTANCE");

    IWbemClassObject* o = obj.Get();
    DefenderRaw raw;
    raw.antivirus_enabled = get_bool(o, L"AntivirusEnabled");
    raw.realtime_enabled = get_bool(o, L"RealTimeProtectionEnabled");
    raw.service_enabled = get_bool(o, L"AMServiceEnabled");
    raw.tamper_protected = get_bool(o, L"IsTamperProtected");
    raw.running_mode = get_string(o, L"AMRunningMode");
    raw.signature_age_days = get_int(o, L"AntivirusSignatureAge");
    raw.signature_version = get_string(o, L"AntivirusSignatureVersion");
    raw.product_version = get_string(o, L"AMProductVersion");
    return interpret_defender(raw, wsc_state, now_utc);
}

}  // namespace metasec::win
