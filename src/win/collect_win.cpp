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
    State wsc_state = State::Unknown;
    for (auto&& c : wsc_checks(now_utc)) {
        wsc_state = c.state;
        r.checks.push_back(std::move(c));
    }
    for (auto&& c : defender_checks(now_utc, wsc_state)) r.checks.push_back(std::move(c));
    return r;
}

AuditInput collect_audit_input(std::chrono::system_clock::time_point now) {
    AuditInput in;
    in.status = collect_status(now);
    in.av_products = av_products_observation();
    return in;
}

}  // namespace metasec::win
