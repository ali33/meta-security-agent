// Registered antivirus products via WMI ROOT\SecurityCenter2 : AntiVirusProduct (read-only
// query, COM, no PowerShell). The namespace exists on client SKUs only; on Windows Server the
// connect fails with WBEM_E_INVALID_NAMESPACE, which is reported as NOT_SUPPORTED.
// This file only fetches raw values; what they mean is decided in core/audit.cpp.
#include <windows.h>
#include <objbase.h>

#include <Wbemidl.h>
#include <comdef.h>
#include <wrl/client.h>

#include <string>

#include "../core/types.hpp"
#include "collect.hpp"
#include "wmi_util.hpp"

namespace metasec::win {

using Microsoft::WRL::ComPtr;

namespace {

AvProductsObservation failed(HRESULT hr) {
    AvProductsObservation o;
    const auto code = static_cast<std::uint32_t>(hr);
    o.obs = classify_failure(code) == State::NotSupported ? Obs::NotSupported : Obs::Unknown;
    o.error_code = hresult_code(code);
    return o;
}

AvProductsObservation failed_code(const char* code) {
    AvProductsObservation o;
    o.obs = Obs::Unknown;
    o.error_code = code;
    return o;
}

}  // namespace

AvProductsObservation av_products_observation() {
    ComPtr<IWbemLocator> locator;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&locator));
    if (FAILED(hr)) return failed(hr);

    ComPtr<IWbemServices> services;
    _bstr_t ns(L"ROOT\\SecurityCenter2");
    hr = locator->ConnectServer(ns, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                                nullptr, nullptr, &services);
    if (FAILED(hr)) return failed(hr);

    hr = CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) return failed(hr);

    ComPtr<IEnumWbemClassObject> en;
    hr = services->ExecQuery(_bstr_t(L"WQL"),
                             _bstr_t(L"SELECT displayName, productState FROM AntiVirusProduct"),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
    if (FAILED(hr)) return failed(hr);

    AvProductsObservation out;
    constexpr std::size_t kMaxProducts = 32;  // bounds an untrusted, vendor-populated list
    for (;;) {
        ComPtr<IWbemClassObject> obj;
        ULONG returned = 0;
        hr = en->Next(10000 /* ms */, 1, &obj, &returned);
        if (FAILED(hr)) return failed(hr);
        if (hr == WBEM_S_TIMEDOUT) return failed_code("TIMEOUT");
        if (returned == 0 || !obj) break;  // enumeration finished (an empty list is a valid answer)
        // A truncated list is not a complete observation: a later entry might be the ON one.
        if (out.products.size() >= kMaxProducts) return failed_code("TRUNCATED");
        const auto name = wmi::get_string(obj.Get(), L"displayName");
        const auto state = wmi::get_int(obj.Get(), L"productState");
        // A product we cannot read is not skipped silently: -1 decodes as UNRECOGNIZED.
        out.products.push_back({name.value_or(""), state.value_or(-1)});
    }
    out.obs = Obs::Observed;
    return out;
}

}  // namespace metasec::win
