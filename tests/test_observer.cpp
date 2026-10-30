// Deterministic tests for the MVP-4 observer: fake snapshots, a real SQLite store in a temp dir,
// injected clock/wait/stop. No OS access.
#include <atomic>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core/observer.hpp"
#include "core/store.hpp"
#include "temp_dir.hpp"

using namespace metasec;
using test_support::TempDir;

namespace {

int g_checks = 0;
int g_failed = 0;

void check(bool ok, const char* expr, const char* file, int line) {
    ++g_checks;
    if (!ok) {
        ++g_failed;
        std::fprintf(stderr, "FAIL %s:%d  %s\n", file, line, expr);
    }
}
#define CHECK(e) check((e), #e, __FILE__, __LINE__)

using Spec = std::vector<std::pair<std::string, State>>;
const State E = State::Enabled, D = State::Disabled, U = State::Unknown;

std::string utc_of(int n) { return std::string("2026-10-30T00:") + (n / 60 < 10 ? "0" : "") + std::to_string(n / 60) + ":" + (n % 60 < 10 ? "0" : "") + std::to_string(n % 60) + "Z"; }

StatusReport report(int n, const Spec& spec, std::size_t evidence_len = 0) {
    StatusReport r;
    r.hostname = "host";
    r.platform = {"windows", "10.0.1", "client"};
    r.observed_at_utc = utc_of(n);
    for (const auto& [id, st] : spec) {
        CheckResult c;
        c.check_id = id;
        c.observed_at_utc = r.observed_at_utc;
        c.state = st;
        c.source = "fake";
        if (st == State::Unknown) c.error_code = "HRESULT:0x80041003";
        if (evidence_len)
            for (int p = 0; p < 16; ++p) c.evidence.emplace_back("k" + std::to_string(p), std::string(evidence_len, 'x'));
        r.checks.push_back(std::move(c));
    }
    return r;
}

// Runs one observer session over `seq` (poll i sees seq[min(i, size-1)]; poll time offset by `t0`).
struct Session {
    ObserverResult result;
    ObserverStatus status;
};

Session run_session(EventStore* store, const std::vector<Spec>& seq, int confirm, int polls, int t0 = 0,
                    std::size_t evidence_len = 0) {
    int i = 0;
    int clock = t0;
    ObserverOptions opt;
    opt.interval_seconds = 30;
    opt.confirm_polls = confirm;
    opt.max_polls = polls;
    opt.version = "9.9.9";
    ObserverHooks h;
    h.snapshot = [&]() {
        const Spec& s = seq[static_cast<std::size_t>(i) < seq.size() ? static_cast<std::size_t>(i) : seq.size() - 1];
        ++i;
        return report(t0 + i, s, evidence_len);
    };
    h.wait = [](int) { return true; };
    h.stop_requested = []() { return false; };
    h.now_utc = [&]() { return utc_of(++clock + 1000); };
    h.now_epoch = [&]() { return 1793363696LL + clock; };
    Observer ob(store, opt, h);
    Session s;
    s.result = ob.run();
    s.status = ob.status();
    return s;
}

int count_kind(EventStore& st, const char* kind) {
    int n = 0;
    for (const auto& e : st.recent_events(500).value)
        if (e.kind == kind) ++n;
    return n;
}

const StoredEvent* find_kind(const std::vector<StoredEvent>& v, const char* kind) {
    for (const auto& e : v)
        if (e.kind == kind) return &e;  // newest first
    return nullptr;
}

bool has_evidence(const StoredEvent& e, const char* k, const char* v) {
    for (const auto& [kk, vv] : e.evidence)
        if (kk == k && vv == v) return true;
    return false;
}

Spec fw(State s) { return {{"firewall.public", s}, {"firewall.private", E}}; }

void test_first_run_baseline_no_events() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    const Session s = run_session(o.store.get(), {fw(E)}, 2, 3);
    CHECK(s.result.stop == ObserverStop::MaxPolls);
    CHECK(s.result.polls == 3);
    CHECK(s.result.events_recorded == 2);  // service_started + service_stopped only
    CHECK(count_kind(*o.store, "change") == 0);
    CHECK(count_kind(*o.store, kLifecycleStarted) == 1);
    CHECK(count_kind(*o.store, kLifecycleStopped) == 1);
    const auto cp = o.store->load_check_states();
    CHECK(cp.value.size() == 2);
    CHECK(o.store->last_observation_utc().value.has_value());
    CHECK(o.store->get_kv(kKvServiceStartedUtc).value.has_value());
    CHECK(o.store->get_kv(kKvLastPollEpoch).value.has_value());
    CHECK(s.status.state == ObserverState::Stopped);
    CHECK(s.status.polls == 3);
    CHECK(s.status.store_errors == 0);
    CHECK(s.status.last_error.empty());
    CHECK(s.status.version == "9.9.9");
    CHECK(s.status.overall.has_value() && *s.status.overall == Overall::Observed);
    CHECK(s.status.last_observation_utc == utc_of(3));
    CHECK(s.status.events_total == 2);
    CHECK(!s.status.started_utc.empty());
}

void test_change_is_stored_once() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    const Session s = run_session(o.store.get(), {fw(E), fw(E), fw(D), fw(D), fw(D), fw(D)}, 2, 6);
    CHECK(count_kind(*o.store, "change") == 1);
    const auto ev = o.store->recent_events(50).value;
    const StoredEvent* c = find_kind(ev, "change");
    CHECK(c != nullptr);
    if (c) {
        CHECK(c->check_id == "firewall.public");
        CHECK(c->from_state == "ENABLED");
        CHECK(c->to_state == "DISABLED");
        CHECK(c->confirmations == 2);
        CHECK(!has_evidence(*c, "detected_after_restart", "true"));
    }
    CHECK(s.status.overall.has_value() && *s.status.overall == Overall::ObservedWithIssues);
}

void test_restart_same_state_no_replay() {
    TempDir t;
    {
        StoreOpen o = EventStore::open(t.file());
        CHECK(o.ok);
        if (!o.ok) return;
        run_session(o.store.get(), {fw(E), fw(D), fw(D)}, 2, 4);
        CHECK(count_kind(*o.store, "change") == 1);
    }
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    const Session s = run_session(o.store.get(), {fw(D)}, 2, 5, 100);
    CHECK(count_kind(*o.store, "change") == 1);  // not replayed
    CHECK(count_kind(*o.store, kLifecycleStarted) == 2);
    CHECK(count_kind(*o.store, kLifecycleStopped) == 2);
    CHECK(s.result.events_recorded == 2);
    CHECK(o.store->load_check_states().value.size() == 2);
    // A third restart with the same state is still silent.
    run_session(o.store.get(), {fw(D)}, 2, 3, 200);
    CHECK(count_kind(*o.store, "change") == 1);
}

void test_change_while_stopped_is_flagged_once() {
    TempDir t;
    {
        StoreOpen o = EventStore::open(t.file());
        CHECK(o.ok);
        if (!o.ok) return;
        run_session(o.store.get(), {fw(E)}, 2, 3);
    }
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    run_session(o.store.get(), {fw(D)}, 2, 4, 100);  // setting differs from the persisted one
    CHECK(count_kind(*o.store, "change") == 1);
    const auto ev = o.store->recent_events(50).value;
    const StoredEvent* c = find_kind(ev, "change");
    CHECK(c != nullptr);
    if (c) {
        CHECK(c->from_state == "ENABLED");
        CHECK(c->to_state == "DISABLED");
        CHECK(has_evidence(*c, "detected_after_restart", "true"));
        CHECK(c->first_observed_at_utc == utc_of(101));
    }
    run_session(o.store.get(), {fw(D)}, 2, 3, 200);
    CHECK(count_kind(*o.store, "change") == 1);
}

void test_restart_confirm_one_is_immediate() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    run_session(o.store.get(), {fw(E)}, 1, 2);
    run_session(o.store.get(), {fw(D)}, 1, 1, 100);
    CHECK(count_kind(*o.store, "change") == 1);
}

void test_boot_time_blip_after_restart_is_not_an_event() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    run_session(o.store.get(), {fw(E)}, 2, 2);
    run_session(o.store.get(), {fw(U), fw(E), fw(E)}, 2, 3, 100);  // WMI not ready at boot
    CHECK(count_kind(*o.store, "change") == 0);
    CHECK(count_kind(*o.store, "observation_lost") == 0);
}

void test_check_added_and_removed_after_restart() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    run_session(o.store.get(), {Spec{{"a", E}, {"b", E}}}, 1, 2);
    run_session(o.store.get(), {Spec{{"a", E}, {"c", D}}}, 1, 2, 100);
    CHECK(count_kind(*o.store, "check_added") == 1);
    CHECK(count_kind(*o.store, "check_removed") == 1);
    const auto st = o.store->load_check_states().value;
    CHECK(st.size() == 2);  // a, c
}

void test_store_unavailable_is_counted_not_fatal() {
    const Session s = run_session(nullptr, {fw(E), fw(D)}, 1, 4);
    CHECK(s.result.stop == ObserverStop::MaxPolls);
    CHECK(s.result.polls == 4);
    CHECK(s.status.store_errors == 4);
    CHECK(s.status.last_error.find("unavailable") != std::string::npos);
    CHECK(s.status.overall.has_value());
}

void test_failing_store_keeps_running_and_exposes_errors() {
    TempDir t;
    StoreLimits lim;
    lim.max_bytes = 256 * 1024;
    StoreOpen o = EventStore::open(t.file(), lim);
    CHECK(o.ok);
    if (!o.ok) return;
    Spec before, after;
    for (int i = 0; i < 300; ++i) {
        before.emplace_back("c" + std::to_string(i), E);
        after.emplace_back("c" + std::to_string(i), D);
    }
    // 300 simultaneous changes with big evidence cannot fit in a 256 KiB store.
    const Session s = run_session(o.store.get(), {before, after, after, after}, 1, 4, 0, 256);
    CHECK(s.result.stop == ObserverStop::MaxPolls);
    CHECK(s.result.polls == 4);
    CHECK(s.status.store_errors >= 1);
    CHECK(s.status.last_error.find("full") != std::string::npos);
    CHECK(s.result.events_recorded < 300);
    CHECK(s.status.state == ObserverState::Stopped);
    // The store is still usable afterwards.
    CHECK(o.store->count_events().ok);
}

void test_snapshot_exception_is_counted_and_loop_continues() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    int calls = 0;
    ObserverOptions opt;
    opt.max_polls = 4;
    opt.confirm_polls = 1;
    ObserverHooks h;
    h.snapshot = [&]() -> StatusReport {
        if (++calls == 2) throw std::runtime_error("wmi exploded");
        return report(calls, fw(E));
    };
    h.wait = [](int) { return true; };
    h.stop_requested = []() { return false; };
    h.now_utc = []() { return std::string("2026-10-30T00:00:00Z"); };
    Observer ob(o.store.get(), opt, h);
    const ObserverResult r = ob.run();
    const ObserverStatus st = ob.status();
    CHECK(r.stop == ObserverStop::MaxPolls);
    CHECK(st.polls == 3);
    CHECK(st.snapshot_errors == 1);
    CHECK(st.last_error.find("wmi exploded") != std::string::npos);
}

void test_stop_hooks_are_deterministic() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    {  // stop_requested before the first snapshot
        ObserverOptions opt;
        ObserverHooks h;
        int snaps = 0;
        h.snapshot = [&]() { ++snaps; return report(1, fw(E)); };
        h.wait = [](int) { return true; };
        h.stop_requested = []() { return true; };
        h.now_utc = []() { return std::string("2026-10-30T00:00:00Z"); };
        Observer ob(o.store.get(), opt, h);
        const ObserverResult r = ob.run();
        CHECK(r.stop == ObserverStop::Interrupted);
        CHECK(snaps == 0);
        CHECK(ob.status().state == ObserverState::Stopped);
    }
    {  // wait() reports a stop request
        ObserverOptions opt;
        ObserverHooks h;
        int snaps = 0;
        h.snapshot = [&]() { ++snaps; return report(snaps, fw(E)); };
        h.wait = [&](int) { return snaps < 2; };
        h.stop_requested = []() { return false; };
        h.now_utc = []() { return std::string("2026-10-30T00:00:01Z"); };
        Observer ob(o.store.get(), opt, h);
        const ObserverResult r = ob.run();
        CHECK(r.stop == ObserverStop::Interrupted);
        CHECK(snaps == 2);
    }
    {  // a throwing hook ends the run with Error, stopped is still recorded
        ObserverOptions opt;
        ObserverHooks h;
        h.snapshot = [&]() { return report(1, fw(E)); };
        h.wait = [](int) -> bool { throw std::runtime_error("wait broke"); };
        h.stop_requested = []() { return false; };
        h.now_utc = []() { return std::string("2026-10-30T00:00:02Z"); };
        Observer ob(o.store.get(), opt, h);
        const ObserverResult r = ob.run();
        CHECK(r.stop == ObserverStop::Error);
        CHECK(r.error.find("wait broke") != std::string::npos);
        CHECK(ob.status().state == ObserverState::Stopped);
    }
    CHECK(count_kind(*o.store, kLifecycleStopped) >= 1);
}

void test_status_is_readable_from_another_thread() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    ObserverOptions opt;
    opt.max_polls = 40;
    opt.confirm_polls = 1;
    int n = 0;
    ObserverHooks h;
    h.snapshot = [&]() { ++n; return report(n, fw(n % 2 ? E : D)); };
    h.wait = [](int) { return true; };
    h.stop_requested = []() { return false; };
    h.now_utc = []() { return std::string("2026-10-30T00:00:00Z"); };
    Observer ob(o.store.get(), opt, h);
    std::atomic<bool> done{false};
    long long last_polls = 0;
    bool monotonic = true;
    std::thread reader([&]() {
        while (!done) {
            const ObserverStatus s = ob.status();
            if (s.polls < last_polls) monotonic = false;
            last_polls = s.polls;
            auto ev = o.store->recent_events(5);  // the IPC thread reads the store too
            (void)ev;
        }
    });
    const ObserverResult r = ob.run();
    done = true;
    reader.join();
    CHECK(monotonic);
    CHECK(r.polls == 40);
    CHECK(ob.status().polls == 40);
}

}  // namespace

int main() {
    test_first_run_baseline_no_events();
    test_change_is_stored_once();
    test_restart_same_state_no_replay();
    test_change_while_stopped_is_flagged_once();
    test_restart_confirm_one_is_immediate();
    test_boot_time_blip_after_restart_is_not_an_event();
    test_check_added_and_removed_after_restart();
    test_store_unavailable_is_counted_not_fatal();
    test_failing_store_keeps_running_and_exposes_errors();
    test_snapshot_exception_is_counted_and_loop_continues();
    test_stop_hooks_are_deterministic();
    test_status_is_readable_from_another_thread();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
