// Defender quick scan (MVP-3), Windows side. Supported interface only: WMI
// ROOT\Microsoft\Windows\Defender : MSFT_MpComputerStatus (read) and MSFT_MpScan.Start (the single
// side effect). No PowerShell. This file only talks to the OS; every decision is in core/scan.cpp.
#define SECURITY_WIN32
#include <windows.h>
#include <objbase.h>
#include <security.h>

#include <Wbemidl.h>
#include <comdef.h>
#include <wrl/client.h>

#include <string>

#include "../core/interpret.hpp"
#include "collect.hpp"
#include "wmi_util.hpp"

namespace metasec::win {

using Microsoft::WRL::ComPtr;

namespace {

constexpr wchar_t kDefenderNs[] = L"ROOT\\Microsoft\\Windows\\Defender";
constexpr long kScanTypeQuick = 1;  // MSFT_MpScan.Start ScanType: 1 = Quick, 2 = Full, 3 = Custom

HRESULT connect_defender(ComPtr<IWbemServices>& services) {
    ComPtr<IWbemLocator> locator;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator));
    if (FAILED(hr)) return hr;
    _bstr_t ns(kDefenderNs);
    hr = locator->ConnectServer(ns, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr,
                                &services);
    if (FAILED(hr)) return hr;
    return CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
}

DefenderScanObservation failed_obs(HRESULT hr) {
    DefenderScanObservation o;
    const auto code = static_cast<std::uint32_t>(hr);
    o.obs = classify_failure(code) == State::NotSupported ? Obs::NotSupported : Obs::Unknown;
    o.error_code = hresult_code(code);
    return o;
}

std::string to_utf8(const std::wstring& w) { return wmi::narrow(w.c_str()); }

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

bool is_console_handle(HANDLE h) {
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    return GetFileType(h) == FILE_TYPE_CHAR && GetConsoleMode(h, &mode) != 0;
}

// Builds MSFT_MpScan.Start's input object with ScanType = quick, using the CIM type the class
// declares (uint8 vs uint32 differ between Windows builds). Unknown type => failure, never a guess.
HRESULT build_start_params(IWbemServices* services, ComPtr<IWbemClassObject>& in_params) {
    ComPtr<IWbemClassObject> cls;
    HRESULT hr = services->GetObject(_bstr_t(L"MSFT_MpScan"), 0, nullptr, &cls, nullptr);
    if (FAILED(hr)) return hr;
    ComPtr<IWbemClassObject> sig;
    hr = cls->GetMethod(L"Start", 0, &sig, nullptr);
    if (FAILED(hr)) return hr;
    if (!sig) return WBEM_E_INVALID_METHOD_PARAMETERS;
    hr = sig->SpawnInstance(0, &in_params);
    if (FAILED(hr)) return hr;
    CIMTYPE type = 0;
    hr = in_params->Get(L"ScanType", 0, nullptr, &type, nullptr);
    if (FAILED(hr)) return hr;
    wmi::Variant v;
    switch (type) {
        case CIM_UINT8:
        case CIM_SINT8:
            v.v.vt = VT_UI1;
            v.v.bVal = static_cast<BYTE>(kScanTypeQuick);
            break;
        case CIM_UINT16:
        case CIM_SINT16:
            v.v.vt = VT_I2;
            v.v.iVal = static_cast<SHORT>(kScanTypeQuick);
            break;
        case CIM_UINT32:
        case CIM_SINT32:
            v.v.vt = VT_I4;
            v.v.lVal = kScanTypeQuick;
            break;
        default:
            return WBEM_E_INVALID_METHOD_PARAMETERS;
    }
    return in_params->Put(L"ScanType", 0, &v.v, 0);
}

}  // namespace

DefenderScanObservation defender_scan_observation() {
    ComPtr<IWbemServices> services;
    HRESULT hr = connect_defender(services);
    if (FAILED(hr)) return failed_obs(hr);

    ComPtr<IEnumWbemClassObject> en;
    hr = services->ExecQuery(_bstr_t(L"WQL"),
                             _bstr_t(L"SELECT AMRunningMode, QuickScanStartTime, QuickScanEndTime FROM MSFT_MpComputerStatus"),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
    if (FAILED(hr)) return failed_obs(hr);

    ComPtr<IWbemClassObject> obj;
    ULONG returned = 0;
    hr = en->Next(10000 /* ms */, 1, &obj, &returned);
    if (FAILED(hr)) return failed_obs(hr);
    DefenderScanObservation o;
    if (hr == WBEM_S_TIMEDOUT) {
        o.error_code = "TIMEOUT";
        return o;
    }
    if (returned == 0 || !obj) {
        o.error_code = "NO_INSTANCE";
        return o;
    }
    o.obs = Obs::Observed;
    o.running_mode = wmi::get_string(obj.Get(), L"AMRunningMode");
    if (const auto s = wmi::get_string(obj.Get(), L"QuickScanStartTime")) o.times.quick_start = parse_cim_datetime(*s);
    if (const auto s = wmi::get_string(obj.Get(), L"QuickScanEndTime")) o.times.quick_end = parse_cim_datetime(*s);
    return o;
}

StartResult start_defender_quick_scan(int timeout_seconds, const std::function<bool()>& stop_requested) {
    StartResult r;
    ComPtr<IWbemServices> services;
    HRESULT hr = connect_defender(services);
    if (FAILED(hr)) {
        r.exec_hr = hr;
        return r;
    }
    ComPtr<IWbemClassObject> in_params;
    hr = build_start_params(services.Get(), in_params);
    if (FAILED(hr)) {
        r.exec_hr = hr;
        return r;
    }

    // Semi-synchronous: returns at once with a call-result object, so we can wait with a bound and
    // honour Ctrl+C. (A synchronous call would block for the whole scan with no way out.)
    ComPtr<IWbemCallResult> call;
    hr = services->ExecMethod(_bstr_t(L"MSFT_MpScan"), _bstr_t(L"Start"), WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
                              in_params.Get(), nullptr, &call);
    if (FAILED(hr)) {
        r.exec_hr = hr;
        return r;
    }
    r.exec_hr = hr;
    if (!call) {  // success without a call object: nothing to wait on, cannot report completion
        r.status_hr = E_POINTER;
        return r;
    }
    CoSetProxyBlanket(call.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout_seconds) * 1000ULL;
    for (;;) {
        if (stop_requested && stop_requested()) {
            r.wait = WaitEnd::Interrupted;
            return r;
        }
        if (GetTickCount64() >= deadline) {
            r.wait = WaitEnd::TimedOut;
            return r;
        }
        LONG status = 0;
        hr = call->GetCallStatus(500, &status);
        if (hr == WBEM_S_TIMEDOUT) continue;
        if (FAILED(hr)) {
            r.status_hr = hr;
            return r;
        }
        r.status_hr = status;
        break;
    }
    if (r.status_hr >= 0) {
        ComPtr<IWbemClassObject> out;
        if (SUCCEEDED(call->GetResultObject(5000, &out)) && out) r.return_value = wmi::get_int(out.Get(), L"ReturnValue");
    }
    return r;
}

ApprovalInput console_approval(const std::string& prompt) {
    ApprovalInput in;
    HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE herr = GetStdHandle(STD_ERROR_HANDLE);
    in.input_is_console = is_console_handle(hin);
    in.output_is_console = is_console_handle(herr);
    // Fail closed before showing or reading anything: a pipe/file/NUL on stdin can never approve.
    if (!in.input_is_console || !in.output_is_console) return in;

    const std::wstring wp = to_wide(prompt);
    DWORD written = 0;
    if (!WriteConsoleW(herr, wp.c_str(), static_cast<DWORD>(wp.size()), &written, nullptr)) {
        in.read = ReadStatus::Error;
        return in;
    }
    DWORD old_mode = 0;
    GetConsoleMode(hin, &old_mode);
    SetConsoleMode(hin, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
    wchar_t buf[128];
    DWORD n = 0;
    const BOOL ok = ReadConsoleW(hin, buf, static_cast<DWORD>(std::size(buf)), &n, nullptr);
    const DWORD err = ok ? 0 : GetLastError();
    FlushConsoleInputBuffer(hin);  // drop any overflow so it cannot leak into the parent shell
    SetConsoleMode(hin, old_mode);
    if (!ok) {
        in.read = err == ERROR_OPERATION_ABORTED ? ReadStatus::Interrupted : ReadStatus::Error;
        return in;
    }
    if (n == 0) {
        in.read = ReadStatus::Eof;
        return in;
    }
    // Ctrl+Z + Enter arrives as a lone 0x1A: not the phrase, so it falls into WRONG_CONFIRMATION.
    in.read = ReadStatus::Ok;
    const std::wstring typed(buf, n);
    // A human cannot type NUL; narrowing would silently cut the line there.
    in.line = typed.find(L'\0') == std::wstring::npos ? to_utf8(typed) : std::string("\x01");
    return in;
}

std::string current_actor() {
    wchar_t name[256];
    ULONG n = static_cast<ULONG>(std::size(name));
    if (GetUserNameExW(NameSamCompatible, name, &n)) return to_utf8(name);
    return "(unknown account)";
}

bool process_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION e{};
    DWORD len = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &e, sizeof(e), &len);
    CloseHandle(token);
    return ok && e.TokenIsElevated != 0;
}

}  // namespace metasec::win
