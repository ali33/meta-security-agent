// Defender-specific state via the supported WMI provider
// ROOT\Microsoft\Windows\Defender : MSFT_MpComputerStatus (read-only query, COM, no PowerShell).
#include <windows.h>
#include <objbase.h>

#include <Wbemidl.h>
#include <comdef.h>
#include <wrl/client.h>

#include <optional>
#include <string>

#include "collect.hpp"

namespace metasec::win {

using Microsoft::WRL::ComPtr;

namespace {

const char* const kSource = "WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpComputerStatus";
const char* const kIdAv = "antivirus.defender.antivirus";
const char* const kIdRt = "antivirus.defender.realtime_protection";

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

std::vector<CheckResult> fail_both(const std::string& now_utc, std::uint32_t hr) {
    return {make_failure(kIdAv, now_utc, kSource, hr), make_failure(kIdRt, now_utc, kSource, hr)};
}

CheckResult bool_check(const char* id, const std::string& now_utc,
                       std::optional<bool> value, const wchar_t* prop_for_error) {
    CheckResult c;
    c.check_id = id;
    c.observed_at_utc = now_utc;
    c.source = kSource;
    if (!value) {
        c.state = State::Unknown;
        c.error_code = "PROPERTY_UNAVAILABLE:" + narrow(prop_for_error);
        return c;
    }
    c.state = *value ? State::Enabled : State::Disabled;
    return c;
}

}  // namespace

std::vector<CheckResult> defender_checks(const std::string& now_utc) {
    ComPtr<IWbemLocator> locator;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&locator));
    if (FAILED(hr)) return fail_both(now_utc, static_cast<std::uint32_t>(hr));

    ComPtr<IWbemServices> services;
    _bstr_t ns(L"ROOT\\Microsoft\\Windows\\Defender");
    hr = locator->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
    if (FAILED(hr)) return fail_both(now_utc, static_cast<std::uint32_t>(hr));

    hr = CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) return fail_both(now_utc, static_cast<std::uint32_t>(hr));

    ComPtr<IEnumWbemClassObject> en;
    hr = services->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT * FROM MSFT_MpComputerStatus"),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
    if (FAILED(hr)) return fail_both(now_utc, static_cast<std::uint32_t>(hr));

    ComPtr<IWbemClassObject> obj;
    ULONG returned = 0;
    hr = en->Next(10000 /* ms */, 1, &obj, &returned);
    if (FAILED(hr)) return fail_both(now_utc, static_cast<std::uint32_t>(hr));
    if (returned == 0 || !obj) {
        // Namespace exists but the provider returned no instance: nothing was observed.
        auto r = fail_both(now_utc, 0x80004005u);
        for (auto& c : r) c.error_code = "NO_INSTANCE";
        return r;
    }

    CheckResult av = bool_check(kIdAv, now_utc, get_bool(obj.Get(), L"AntivirusEnabled"), L"AntivirusEnabled");
    CheckResult rt = bool_check(kIdRt, now_utc, get_bool(obj.Get(), L"RealTimeProtectionEnabled"),
                                L"RealTimeProtectionEnabled");

    // Context for interpreting the two checks. Passive/SxS mode means another AV is primary.
    if (auto s = get_bool(obj.Get(), L"AMServiceEnabled")) av.evidence.emplace_back("am_service_enabled", *s ? "true" : "false");
    if (auto s = get_string(obj.Get(), L"AMRunningMode")) av.evidence.emplace_back("am_running_mode", *s);
    if (auto n = get_int(obj.Get(), L"AntivirusSignatureAge"); n && *n != 65535) av.evidence.emplace_back("signature_age_days", std::to_string(*n));
    if (auto s = get_string(obj.Get(), L"AntivirusSignatureVersion")) av.evidence.emplace_back("signature_version", *s);
    if (auto s = get_string(obj.Get(), L"AMProductVersion")) av.evidence.emplace_back("am_product_version", *s);
    if (auto s = get_bool(obj.Get(), L"IsTamperProtected")) rt.evidence.emplace_back("tamper_protected", *s ? "true" : "false");

    return {std::move(av), std::move(rt)};
}

}  // namespace metasec::win
