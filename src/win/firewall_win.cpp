#include <windows.h>
#include <objbase.h>

#include <netfw.h>
#include <wrl/client.h>

#include "collect.hpp"

namespace metasec::win {

using Microsoft::WRL::ComPtr;

std::vector<CheckResult> firewall_checks(const std::string& now_utc) {
    static const char* kSource = "INetFwPolicy2";
    const struct {
        const char* id;
        NET_FW_PROFILE_TYPE2 type;
    } profiles[] = {{"firewall.domain", NET_FW_PROFILE2_DOMAIN},
                    {"firewall.private", NET_FW_PROFILE2_PRIVATE},
                    {"firewall.public", NET_FW_PROFILE2_PUBLIC}};

    std::vector<CheckResult> out;
    ComPtr<INetFwPolicy2> policy;
    const HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                        IID_PPV_ARGS(&policy));
    if (FAILED(hr) || !policy) {
        for (const auto& p : profiles)
            out.push_back(make_failure(p.id, now_utc, kSource, static_cast<std::uint32_t>(hr)));
        return out;
    }
    for (const auto& p : profiles) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        const HRESULT r = policy->get_FirewallEnabled(p.type, &enabled);
        if (FAILED(r)) {
            out.push_back(make_failure(p.id, now_utc, kSource, static_cast<std::uint32_t>(r)));
            continue;
        }
        CheckResult c;
        c.check_id = p.id;
        c.observed_at_utc = now_utc;
        c.source = kSource;
        c.state = enabled != VARIANT_FALSE ? State::Enabled : State::Disabled;
        out.push_back(std::move(c));
    }
    return out;
}

}  // namespace metasec::win
