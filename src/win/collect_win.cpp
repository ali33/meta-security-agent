#include "collect.hpp"

#include "../core/render.hpp"

namespace metasec::win {

StatusReport collect_status(std::chrono::system_clock::time_point now) {
    StatusReport r;
    const std::string now_utc = format_utc(now);
    r.observed_at_utc = now_utc;
    r.hostname = host_name();
    r.platform = platform_info();
    for (auto&& c : firewall_checks(now_utc)) r.checks.push_back(std::move(c));
    for (auto&& c : wsc_checks(now_utc)) r.checks.push_back(std::move(c));
    for (auto&& c : defender_checks(now_utc)) r.checks.push_back(std::move(c));
    return r;
}

}  // namespace metasec::win
