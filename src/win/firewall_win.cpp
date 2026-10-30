#include <windows.h>
#include <objbase.h>

#include <netfw.h>
#include <wrl/client.h>

#include "../core/interpret.hpp"
#include "collect.hpp"

namespace metasec::win {

using Microsoft::WRL::ComPtr;

std::vector<CheckResult> firewall_checks(const std::string& now_utc) {
    const struct {
        const char* id;
        NET_FW_PROFILE_TYPE2 type;
    } profiles[] = {{kIdFwDomain, NET_FW_PROFILE2_DOMAIN},
                    {kIdFwPrivate, NET_FW_PROFILE2_PRIVATE},
                    {kIdFwPublic, NET_FW_PROFILE2_PUBLIC}};

    std::vector<CheckResult> out;
    ComPtr<INetFwPolicy2> policy;
    const HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                        IID_PPV_ARGS(&policy));
    if (FAILED(hr) || !policy) {
        const HRESULT fail = FAILED(hr) ? hr : E_POINTER;
        for (const auto& p : profiles) out.push_back(interpret_firewall_profile(p.id, now_utc, fail, false));
        return out;
    }
    for (const auto& p : profiles) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        const HRESULT r = policy->get_FirewallEnabled(p.type, &enabled);
        out.push_back(interpret_firewall_profile(p.id, now_utc, r, enabled != VARIANT_FALSE));
    }
    return out;
}

}  // namespace metasec::win
