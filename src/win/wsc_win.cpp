#include <windows.h>
#include <objbase.h>

#include <wscapi.h>

#include "../core/interpret.hpp"
#include "collect.hpp"

namespace metasec::win {

// Windows Security Center aggregate antivirus health. This is the health of whichever
// AV product(s) registered with WSC, NOT a Defender-specific verdict (see defender_win.cpp).
std::vector<CheckResult> wsc_checks(const std::string& now_utc) {
    WSC_SECURITY_PROVIDER_HEALTH health = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
    const HRESULT hr = WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS, &health);
    return {interpret_wsc(now_utc, hr, static_cast<int>(health))};
}

}  // namespace metasec::win
