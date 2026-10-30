// Small helpers for reading WMI properties. Header-only; used by the read-only WMI providers.
#pragma once
#include <windows.h>

#include <Wbemidl.h>

#include <optional>
#include <string>

namespace metasec::win::wmi {

struct Variant {
    VARIANT v;
    Variant() { VariantInit(&v); }
    ~Variant() { VariantClear(&v); }
    Variant(const Variant&) = delete;
    Variant& operator=(const Variant&) = delete;
};

inline std::string narrow(const wchar_t* w) {
    if (!w) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<std::size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

inline std::optional<bool> get_bool(IWbemClassObject* o, const wchar_t* name) {
    Variant var;
    if (FAILED(o->Get(name, 0, &var.v, nullptr, nullptr)) || var.v.vt != VT_BOOL) return std::nullopt;
    return var.v.boolVal != VARIANT_FALSE;
}

inline std::optional<long long> get_int(IWbemClassObject* o, const wchar_t* name) {
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

inline std::optional<std::string> get_string(IWbemClassObject* o, const wchar_t* name) {
    Variant var;
    if (FAILED(o->Get(name, 0, &var.v, nullptr, nullptr)) || var.v.vt != VT_BSTR || !var.v.bstrVal)
        return std::nullopt;
    return narrow(var.v.bstrVal);
}

}  // namespace metasec::win::wmi
