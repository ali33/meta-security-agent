#include <windows.h>
#include <objbase.h>

#include <wscapi.h>

#include "collect.hpp"

namespace metasec::win {

// Windows Security Center aggregate antivirus health. This is the health of whichever
// AV product(s) registered with WSC, NOT a Defender-specific verdict (see defender_win.cpp).
std::vector<CheckResult> wsc_checks(const std::string& now_utc) {
    static const char* kSource = "WscGetSecurityProviderHealth";
    static const char* kId = "antivirus.windows_security_center";

    WSC_SECURITY_PROVIDER_HEALTH health = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
    const HRESULT hr = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS, &health);
    if (FAILED(hr)) return {make_failure(kId, now_utc, kSource, static_cast<std::uint32_t>(hr))};

    CheckResult c;
    c.check_id = kId;
    c.observed_at_utc = now_utc;
    c.source = kSource;
    c.state = wsc_health_to_state(static_cast<int>(health));
    return {std::move(c)};
}

}  // namespace metasec::win
