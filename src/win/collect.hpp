#pragma once
#include <chrono>
#include <string>
#include <vector>

#include "../core/audit.hpp"
#include "../core/types.hpp"

namespace metasec::win {

// RAII COM apartment. Construct once on the thread that will run all providers
// (the main thread); every COM pointer used by providers is created, used and released
// on that same thread inside the apartment's lifetime. Nothing crosses threads.
class ComApartment {
public:
    ComApartment();
    ~ComApartment();
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;
    // HRESULT of CoInitializeEx (S_OK / S_FALSE mean usable).
    long result() const { return hr_; }
    // HRESULT of CoInitializeSecurity (RPC_E_TOO_LATE is normal and reported as S_OK).
    long security_result() const { return sec_hr_; }
    bool ok() const { return hr_ >= 0; }

private:
    long hr_;
    long sec_hr_ = 0;
    bool owns_;
};

std::string host_name();
PlatformInfo platform_info();

// Each provider returns one or more checks; failures never yield a positive state.
std::vector<CheckResult> firewall_checks(const std::string& now_utc);
std::vector<CheckResult> wsc_checks(const std::string& now_utc);
// `wsc_state` is the already-observed Security Center state, used only to tell
// "Defender off because another AV is healthy" from "Defender off, nothing protecting".
std::vector<CheckResult> defender_checks(const std::string& now_utc, State wsc_state);

// Registered antivirus products from Security Center (client SKUs only; Server => NOT_SUPPORTED).
AvProductsObservation av_products_observation();

// Runs all providers. Requires a live ComApartment on the calling thread.
StatusReport collect_status(std::chrono::system_clock::time_point now);

// status data plus the registered-AV list, for `audit`. Requires a live ComApartment.
AuditInput collect_audit_input(std::chrono::system_clock::time_point now);

}  // namespace metasec::win
