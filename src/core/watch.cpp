#include "watch.hpp"

#include <format>

#include "json.hpp"
#include "render.hpp"

namespace metasec {

namespace {

bool unobserved(State s) { return s == State::Unknown || s == State::NotSupported; }

WatchEventKind classify(const std::optional<State>& from, const std::optional<State>& to) {
    if (!from) return WatchEventKind::CheckAdded;
    if (!to) return WatchEventKind::CheckRemoved;
    if (unobserved(*to) && !unobserved(*from)) return WatchEventKind::ObservationLost;
    if (unobserved(*from) && !unobserved(*to)) return WatchEventKind::ObservationRestored;
    return WatchEventKind::Change;
}

std::string q(std::string_view s) { return "\"" + json_escape(s) + "\""; }

std::string state_json(const std::optional<State>& s) { return s ? q(to_string(*s)) : "null"; }
std::string posture_json(const std::optional<State>& s) { return s ? q(to_string(posture_of(*s))) : "null"; }
std::string state_text(const std::optional<State>& s) { return s ? to_string(*s) : "(absent)"; }

std::string evidence_json(const std::vector<std::pair<std::string, std::string>>& ev) {
    std::string o = "{";
    bool first = true;
    for (const auto& [k, v] : ev) {
        if (!first) o += ',';
        first = false;
        o += q(k) + ":" + q(v);
    }
    return o + "}";
}

// Terminal-safe: control characters never reach the console.
std::string printable(std::string_view s) {
    std::string o;
    for (char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        o += (u < 0x20 || u == 0x7F) ? '?' : c;
    }
    return o;
}

std::string head_json(const char* event, const std::string& at) {
    return std::format(R"({{"schema_version":{},"command":"watch","event":"{}","observed_at_utc":{})",
                       kSchemaVersion, event, q(at));
}

}  // namespace

const char* to_string(WatchEventKind k) {
    switch (k) {
        case WatchEventKind::Change: return "change";
        case WatchEventKind::ObservationLost: return "observation_lost";
        case WatchEventKind::ObservationRestored: return "observation_restored";
        case WatchEventKind::CheckAdded: return "check_added";
        case WatchEventKind::CheckRemoved: return "check_removed";
    }
    return "change";
}

const char* to_string(WatchStop s) {
    switch (s) {
        case WatchStop::MaxPolls: return "max_polls";
        case WatchStop::Interrupted: return "interrupted";
        case WatchStop::OutputFailed: return "output_failed";
    }
    return "max_polls";
}

// --- tracker ----------------------------------------------------------------------------------

WatchTracker::WatchTracker(int confirm_polls) : confirm_(confirm_polls < 1 ? 1 : confirm_polls) {}

void WatchTracker::set_baseline(const StatusReport& r) {
    entries_.clear();
    for (const auto& c : r.checks) {
        bool dup = false;
        for (const auto& e : entries_) dup = dup || e.id == c.check_id;
        if (dup) continue;  // first occurrence wins
        Entry e;
        e.id = c.check_id;
        e.confirmed = c.state;
        e.last = c;
        entries_.push_back(std::move(e));
    }
    baseline_ = true;
}

std::vector<WatchEvent> WatchTracker::observe(const StatusReport& r) {
    std::vector<WatchEvent> events;
    if (!baseline_) {
        set_baseline(r);
        return events;
    }
    // Current check per id (first occurrence wins), in report order.
    std::vector<const CheckResult*> cur;
    for (const auto& c : r.checks) {
        bool dup = false;
        for (const auto* p : cur) dup = dup || p->check_id == c.check_id;
        if (!dup) cur.push_back(&c);
    }
    auto find_cur = [&](const std::string& id) -> const CheckResult* {
        for (const auto* p : cur)
            if (p->check_id == id) return p;
        return nullptr;
    };
    auto find_entry = [&](const std::string& id) -> Entry* {
        for (auto& e : entries_)
            if (e.id == id) return &e;
        return nullptr;
    };
    // Every current id gets an entry first (new ids start as "absent"); only then are
    // pointers into entries_ taken, so they stay valid.
    for (const auto* c : cur) {
        if (!find_entry(c->check_id)) {
            Entry e;
            e.id = c->check_id;
            entries_.push_back(std::move(e));
        }
    }
    // Report order first, then ids that are no longer reported.
    std::vector<Entry*> order;
    for (const auto* c : cur) order.push_back(find_entry(c->check_id));
    for (auto& e : entries_)
        if (!find_cur(e.id)) order.push_back(&e);

    std::vector<Entry> kept;
    for (Entry* ep : order) {
        Entry& e = *ep;
        const CheckResult* c = find_cur(e.id);
        const std::optional<State> obs = c ? std::optional<State>(c->state) : std::nullopt;
        if (obs == e.confirmed) {
            // Back to the confirmed value: any pending candidate was a blip.
            e.has_candidate = false;
            e.count = 0;
            if (c) e.last = *c;
        } else {
            if (e.has_candidate && e.candidate == obs) {
                ++e.count;
            } else {
                e.has_candidate = true;
                e.candidate = obs;
                e.count = 1;
                e.first_utc = r.observed_at_utc;
            }
            if (e.count >= confirm_) {
                WatchEvent ev;
                ev.kind = classify(e.confirmed, obs);
                ev.observed_at_utc = r.observed_at_utc;
                ev.first_observed_at_utc = e.first_utc;
                ev.check_id = e.id;
                ev.from = e.confirmed;
                ev.to = obs;
                ev.confirmations = e.count;
                const CheckResult& basis = c ? *c : e.last;
                ev.source = basis.source;
                ev.error_code = c ? c->error_code : std::string();
                ev.evidence = basis.evidence;
                events.push_back(std::move(ev));
                e.confirmed = obs;
                e.has_candidate = false;
                e.count = 0;
                if (c) e.last = *c;
            }
        }
        // An entry that is absent and stays absent carries nothing: drop it.
        if (e.confirmed || e.has_candidate) kept.push_back(e);
    }
    entries_ = std::move(kept);
    return events;
}

// --- rendering --------------------------------------------------------------------------------

std::string render_watch_baseline_json(const StatusReport& r, const WatchOptions& opt, const std::string& version) {
    std::string o = head_json("baseline", r.observed_at_utc);
    o += std::format(R"(,"product":{},"version":{},"mode":"standalone","hostname":{},)", q(kProduct), q(version),
                     q(r.hostname));
    o += std::format(R"("platform":{{"os":{},"version":{},"kind":{}}},)", q(r.platform.os), q(r.platform.version),
                     q(r.platform.kind));
    o += std::format(R"("interval_seconds":{},"confirm_polls":{},"checks":[)", opt.interval_seconds,
                     opt.confirm_polls);
    bool first = true;
    for (const auto& c : r.checks) {
        if (!first) o += ',';
        first = false;
        o += std::format(R"({{"check_id":{},"state":{},"posture":{},"source":{},"error_code":{},"evidence":{}}})",
                         q(c.check_id), q(to_string(c.state)), q(to_string(posture_of(c.state))), q(c.source),
                         q(c.error_code), evidence_json(c.evidence));
    }
    return o + "]}\n";
}

std::string render_watch_event_json(const WatchEvent& e) {
    std::string o = head_json(to_string(e.kind), e.observed_at_utc);
    o += std::format(
        R"(,"first_observed_at_utc":{},"check_id":{},"from":{},"to":{},"from_posture":{},"to_posture":{},)"
        R"("confirmations":{},"source":{},"error_code":{},"evidence":{}}})",
        q(e.first_observed_at_utc), q(e.check_id), state_json(e.from), state_json(e.to), posture_json(e.from),
        posture_json(e.to), e.confirmations, q(e.source), q(e.error_code), evidence_json(e.evidence));
    return o + "\n";
}

std::string render_watch_stopped_json(const std::string& at_utc, const WatchResult& res) {
    return head_json("stopped", at_utc) +
           std::format(R"(,"reason":"{}","polls":{},"events":{}}})", to_string(res.stop), res.polls, res.events) +
           "\n";
}

std::string render_watch_baseline_text(const StatusReport& r, const WatchOptions& opt, const std::string& version) {
    std::string o = std::format("{} v{} | Standalone | Read-only | Watch\n", kProduct, version);
    o += std::format("{} [BASELINE] host {} | {} {} ({}) | every {}s, confirm {} polls\n", r.observed_at_utc,
                     printable(r.hostname), r.platform.os, r.platform.version, r.platform.kind, opt.interval_seconds,
                     opt.confirm_polls);
    for (const auto& c : r.checks)
        o += std::format("  {}: {} ({}){}\n", printable(c.check_id), to_string(c.state),
                         to_string(posture_of(c.state)),
                         c.error_code.empty() ? std::string() : " error " + printable(c.error_code));
    return o;
}

std::string render_watch_event_text(const WatchEvent& e) {
    const char* tag = "CHANGE";
    switch (e.kind) {
        case WatchEventKind::Change: break;
        case WatchEventKind::ObservationLost: tag = "OBSERVATION LOST"; break;
        case WatchEventKind::ObservationRestored: tag = "OBSERVATION RESTORED"; break;
        case WatchEventKind::CheckAdded: tag = "CHECK ADDED"; break;
        case WatchEventKind::CheckRemoved: tag = "CHECK REMOVED"; break;
    }
    std::string o = std::format("{} [{}] {}: {} -> {}", e.observed_at_utc, tag, printable(e.check_id),
                                state_text(e.from), state_text(e.to));
    if (e.to) o += std::format(" ({})", to_string(posture_of(*e.to)));
    if (e.kind == WatchEventKind::ObservationLost)
        o += " - could not be read; the setting itself is not known to have changed";
    if (!e.error_code.empty()) o += " error " + printable(e.error_code);
    return o + "\n";
}

std::string render_watch_stopped_text(const std::string& at_utc, const WatchResult& res) {
    return std::format("{} [STOPPED] {} after {} polls, {} change events\n", at_utc, to_string(res.stop), res.polls,
                       res.events);
}

// --- loop -------------------------------------------------------------------------------------

WatchResult run_watch(const WatchOptions& opt, const WatchHooks& hooks, const std::string& version) {
    WatchResult res;
    WatchTracker tracker(opt.confirm_polls);
    for (;;) {
        if (hooks.stop_requested()) {
            res.stop = WatchStop::Interrupted;
            break;
        }
        const StatusReport r = hooks.snapshot();
        ++res.polls;
        res.last_overall = compute_overall(r.checks);
        if (!tracker.has_baseline()) {
            tracker.set_baseline(r);
            const std::string line =
                opt.json ? render_watch_baseline_json(r, opt, version) : render_watch_baseline_text(r, opt, version);
            if (!hooks.emit(line)) {
                res.stop = WatchStop::OutputFailed;
                return res;
            }
        } else {
            for (const auto& ev : tracker.observe(r)) {
                ++res.events;
                if (!hooks.emit(opt.json ? render_watch_event_json(ev) : render_watch_event_text(ev))) {
                    res.stop = WatchStop::OutputFailed;
                    return res;
                }
            }
        }
        if (opt.max_polls > 0 && res.polls >= opt.max_polls) {
            res.stop = WatchStop::MaxPolls;
            break;
        }
        if (!hooks.wait(opt.interval_seconds)) {
            res.stop = WatchStop::Interrupted;
            break;
        }
    }
    const std::string at = hooks.now_utc();
    if (!hooks.emit(opt.json ? render_watch_stopped_json(at, res) : render_watch_stopped_text(at, res)))
        res.stop = WatchStop::OutputFailed;
    return res;
}

}  // namespace metasec
