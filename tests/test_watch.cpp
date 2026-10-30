// Deterministic tests for MVP-2 change detection and the watch loop (fake snapshots, no OS).
// `metasec_watch_tests --emit-ndjson` prints a hostile NDJSON stream; CTest parses every line
// with CMake's own JSON parser (tests/watch_ndjson_roundtrip.cmake).
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/cli.hpp"
#include "core/watch.hpp"

using namespace metasec;

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

// Poll n has timestamp 2026-10-30T00:00:<n>Z.
std::string utc_of(int n) { return std::string("2026-10-30T00:00:") + (n < 10 ? "0" : "") + std::to_string(n) + "Z"; }

StatusReport report(int n, const Spec& spec) {
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
        c.evidence = {{"n", std::to_string(n)}};
        r.checks.push_back(std::move(c));
    }
    return r;
}

const State E = State::Enabled, D = State::Disabled, U = State::Unknown;

Spec fw(State s) { return {{"firewall.public", s}, {"firewall.private", E}}; }

// Feeds states of firewall.public (poll 0 is the baseline) and returns every event.
std::vector<WatchEvent> run_states(int confirm, const std::vector<State>& seq) {
    WatchTracker t(confirm);
    std::vector<WatchEvent> all;
    for (std::size_t i = 0; i < seq.size(); ++i) {
        const StatusReport r = report(static_cast<int>(i), fw(seq[i]));
        if (i == 0) {
            t.set_baseline(r);
            continue;
        }
        for (auto& e : t.observe(r)) all.push_back(std::move(e));
    }
    return all;
}

void test_no_change() {
    CHECK(run_states(2, {E, E, E, E, E, E}).empty());
    CHECK(run_states(1, {D, D, D, D}).empty());  // baseline DISABLED is not an event, nor is staying so
}

void test_single_change_single_event() {
    const auto ev = run_states(2, {E, E, D, D, D, D, D});
    CHECK(ev.size() == 1);
    if (ev.size() != 1) return;
    CHECK(ev[0].kind == WatchEventKind::Change);
    CHECK(ev[0].check_id == "firewall.public");
    CHECK(ev[0].from == E && ev[0].to == D);
    CHECK(ev[0].first_observed_at_utc == utc_of(2));
    CHECK(ev[0].observed_at_utc == utc_of(3));  // confirmed by the second consecutive poll
    CHECK(ev[0].confirmations == 2);
    CHECK(ev[0].source == "fake");
    CHECK(!ev[0].evidence.empty());
}

void test_confirm_one_is_immediate() {
    const auto ev = run_states(1, {E, E, D, D});
    CHECK(ev.size() == 1);
    if (ev.size() == 1) {
        CHECK(ev[0].observed_at_utc == utc_of(2));
        CHECK(ev[0].first_observed_at_utc == utc_of(2));
    }
}

void test_change_and_back_gives_two_events() {
    const auto ev = run_states(2, {E, D, D, D, E, E, E});
    CHECK(ev.size() == 2);
    if (ev.size() == 2) {
        CHECK(ev[0].from == E && ev[0].to == D);
        CHECK(ev[1].from == D && ev[1].to == E);
    }
}

void test_flapping_is_suppressed() {
    CHECK(run_states(2, {E, D, E, D, E, D, E, D, E}).empty());
    // With confirm 3 a value must hold for three polls.
    CHECK(run_states(3, {E, D, D, E, D, D, E, D, D, E}).empty());
    CHECK(run_states(3, {E, D, D, D}).size() == 1);
}

void test_candidate_restarts_when_it_changes() {
    // E -> D, then P (not D): the D count must not carry over to P.
    const State P = State::Poor;
    const auto ev = run_states(2, {E, D, P, D, P, P});
    CHECK(ev.size() == 1);
    if (ev.size() == 1) {
        CHECK(ev[0].to == P);
        CHECK(ev[0].first_observed_at_utc == utc_of(4));
    }
}

void test_transient_unknown_is_not_reported() {
    CHECK(run_states(2, {E, U, E, E, U, E, E}).empty());
}

void test_persistent_unknown_is_lost_not_disabled() {
    const auto ev = run_states(2, {E, U, U, U, U});
    CHECK(ev.size() == 1);
    if (ev.size() != 1) return;
    CHECK(ev[0].kind == WatchEventKind::ObservationLost);
    CHECK(ev[0].from == E && ev[0].to == U);
    CHECK(!ev[0].error_code.empty());
    CHECK(render_watch_event_text(ev[0]).find("DISABLED") == std::string::npos);
    CHECK(render_watch_event_json(ev[0]).find("DISABLED") == std::string::npos);
}

void test_recovery_after_unknown() {
    const auto ev = run_states(2, {E, U, U, E, E, E});
    CHECK(ev.size() == 2);
    if (ev.size() != 2) return;
    CHECK(ev[0].kind == WatchEventKind::ObservationLost);
    CHECK(ev[1].kind == WatchEventKind::ObservationRestored);
    CHECK(ev[1].from == U && ev[1].to == E);
    // Unknown that resolves to a different real state is a restoration with the new state.
    const auto ev2 = run_states(2, {E, U, U, D, D});
    CHECK(ev2.size() == 2 && ev2[1].kind == WatchEventKind::ObservationRestored && ev2[1].to == D);
}

void test_unobserved_to_not_supported_is_plain_change() {
    const auto ev = run_states(2, {U, U, State::NotSupported, State::NotSupported});
    CHECK(ev.size() == 1);
    if (ev.size() == 1) CHECK(ev[0].kind == WatchEventKind::Change);
}

void test_unknown_in_baseline() {
    const auto ev = run_states(2, {U, U, E, E, E});
    CHECK(ev.size() == 1);
    if (ev.size() == 1) CHECK(ev[0].kind == WatchEventKind::ObservationRestored);
}

void test_added_and_removed_checks() {
    WatchTracker t(2);
    t.set_baseline(report(0, {{"a", E}}));
    CHECK(t.observe(report(1, {{"a", E}, {"b", D}})).empty());  // first sight of b: pending
    auto ev = t.observe(report(2, {{"a", E}, {"b", D}}));
    CHECK(ev.size() == 1);
    if (ev.size() == 1) {
        CHECK(ev[0].kind == WatchEventKind::CheckAdded);
        CHECK(!ev[0].from && ev[0].to == D && ev[0].check_id == "b");
        CHECK(ev[0].first_observed_at_utc == utc_of(1));
    }
    CHECK(t.observe(report(3, {{"a", E}, {"b", D}})).empty());
    CHECK(t.observe(report(4, {{"a", E}})).empty());  // b missing once: pending
    ev = t.observe(report(5, {{"a", E}}));
    CHECK(ev.size() == 1);
    if (ev.size() == 1) {
        CHECK(ev[0].kind == WatchEventKind::CheckRemoved);
        CHECK(ev[0].from == D && !ev[0].to && ev[0].check_id == "b");
        CHECK(!ev[0].evidence.empty());  // evidence of the last value seen
    }
    CHECK(t.observe(report(6, {{"a", E}})).empty());
    CHECK(t.observe(report(7, {{"a", E}})).empty());
    // A check that appears for one poll only never produces an event.
    WatchTracker t2(2);
    t2.set_baseline(report(0, {{"a", E}}));
    CHECK(t2.observe(report(1, {{"a", E}, {"x", E}})).empty());
    CHECK(t2.observe(report(2, {{"a", E}})).empty());
    CHECK(t2.observe(report(3, {{"a", E}})).empty());
}

void test_duplicate_ids_first_wins() {
    WatchTracker t(1);
    t.set_baseline(report(0, {{"a", E}, {"a", D}}));
    CHECK(t.observe(report(1, {{"a", E}, {"a", D}})).empty());
}

void test_observe_before_baseline_sets_it() {
    WatchTracker t(1);
    CHECK(!t.has_baseline());
    CHECK(t.observe(report(0, fw(D))).empty());
    CHECK(t.has_baseline());
    CHECK(t.observe(report(1, fw(D))).empty());
    CHECK(t.observe(report(2, fw(E))).size() == 1);
}

void test_independent_checks_each_get_one_event() {
    WatchTracker t(2);
    t.set_baseline(report(0, {{"a", E}, {"b", E}, {"c", E}}));
    t.observe(report(1, {{"a", D}, {"b", E}, {"c", U}}));
    const auto ev = t.observe(report(2, {{"a", D}, {"b", E}, {"c", U}}));
    CHECK(ev.size() == 2);
    if (ev.size() == 2) {
        CHECK(ev[0].check_id == "a" && ev[0].kind == WatchEventKind::Change);
        CHECK(ev[1].check_id == "c" && ev[1].kind == WatchEventKind::ObservationLost);
    }
}

// Long deterministic sweep: events never exceed transitions and never repeat a confirmed value.
void test_invariants_sweep() {
    const State all[] = {E, D, U, State::Poor, State::NotSupported};
    for (int confirm = 1; confirm <= 3; ++confirm) {
        unsigned seed = 12345u + static_cast<unsigned>(confirm);
        WatchTracker t(confirm);
        State confirmed = E;
        t.set_baseline(report(0, {{"x", confirmed}}));
        for (int i = 1; i < 2000; ++i) {
            seed = seed * 1103515245u + 12345u;
            const State s = all[(seed >> 16) % 5];
            for (const auto& e : t.observe(report(i % 60, {{"x", s}}))) {
                CHECK(e.from == confirmed);
                CHECK(e.to && *e.to != confirmed);
                CHECK(e.confirmations >= confirm);
                confirmed = *e.to;
            }
        }
    }
}

// --- loop -------------------------------------------------------------------------------------

struct Fake {
    std::vector<StatusReport> script;  // consumed in order; last one repeats
    std::size_t next = 0;
    std::vector<std::string> lines;
    int waits = 0;
    int fail_emit_at = -1;       // 1-based index of the emit call to fail
    int interrupt_wait_at = -1;  // 1-based wait call that reports a stop
    int stop_before_poll = -1;   // 1-based snapshot index before which stop is requested
    int emits = 0;

    WatchHooks hooks() {
        WatchHooks h;
        h.snapshot = [this] {
            const StatusReport r = script[next < script.size() ? next : script.size() - 1];
            ++next;
            return r;
        };
        h.emit = [this](const std::string& s) {
            ++emits;
            if (emits == fail_emit_at) return false;
            lines.push_back(s);
            return true;
        };
        h.wait = [this](int) {
            ++waits;
            return waits != interrupt_wait_at;
        };
        h.stop_requested = [this] { return stop_before_poll > 0 && static_cast<int>(next) + 1 == stop_before_poll; };
        h.now_utc = [] { return std::string("2026-10-30T01:00:00Z"); };
        return h;
    }
};

WatchOptions opts(int max_polls, int confirm, bool json = true) {
    WatchOptions o;
    o.json = json;
    o.interval_seconds = 1;
    o.max_polls = max_polls;
    o.confirm_polls = confirm;
    return o;
}

void test_loop_one_change_one_alert() {
    Fake f;
    for (int i = 0; i < 6; ++i) f.script.push_back(report(i, fw(i < 3 ? E : D)));
    const WatchResult r = run_watch(opts(6, 2), f.hooks(), "t");
    CHECK(r.stop == WatchStop::MaxPolls);
    CHECK(r.polls == 6);
    CHECK(r.events == 1);
    CHECK(f.waits == 5);                  // no wait after the last poll
    CHECK(f.lines.size() == 3);           // baseline + 1 change + stopped
    if (f.lines.size() == 3) {
        CHECK(f.lines[0].find("\"event\":\"baseline\"") != std::string::npos);
        CHECK(f.lines[1].find("\"event\":\"change\"") != std::string::npos);
        CHECK(f.lines[1].find("\"from\":\"ENABLED\",\"to\":\"DISABLED\"") != std::string::npos);
        CHECK(f.lines[2].find("\"event\":\"stopped\"") != std::string::npos);
        CHECK(f.lines[2].find("\"reason\":\"max_polls\"") != std::string::npos);
    }
    for (const auto& l : f.lines) {
        CHECK(!l.empty() && l.back() == '\n' && l.find('\n') == l.size() - 1);  // exactly one line
    }
    CHECK(r.last_overall && *r.last_overall == Overall::ObservedWithIssues);
}

void test_loop_no_change_only_baseline_and_stopped() {
    Fake f;
    f.script.push_back(report(0, fw(E)));
    const WatchResult r = run_watch(opts(20, 2), f.hooks(), "t");
    CHECK(r.polls == 20 && r.events == 0);
    CHECK(f.lines.size() == 2);
    CHECK(r.last_overall && *r.last_overall == Overall::Observed);
}

void test_loop_text_mode() {
    Fake f;
    for (int i = 0; i < 4; ++i) f.script.push_back(report(i, fw(i < 2 ? E : D)));
    run_watch(opts(4, 1, false), f.hooks(), "t");
    CHECK(f.lines.size() == 3);
    if (f.lines.size() == 3) {
        CHECK(f.lines[0].find("[BASELINE]") != std::string::npos);
        CHECK(f.lines[1].find("[CHANGE] firewall.public: ENABLED -> DISABLED (ATTENTION)") != std::string::npos);
        CHECK(f.lines[2].find("[STOPPED] max_polls after 4 polls, 1 change events") != std::string::npos);
    }
}

void test_loop_interrupted_in_wait() {
    Fake f;
    f.script.push_back(report(0, fw(E)));
    f.interrupt_wait_at = 3;
    const WatchResult r = run_watch(opts(0, 2), f.hooks(), "t");
    CHECK(r.stop == WatchStop::Interrupted);
    CHECK(r.polls == 3);
    CHECK(f.lines.size() == 2);
    CHECK(f.lines.back().find("\"reason\":\"interrupted\"") != std::string::npos);
}

void test_loop_interrupted_before_first_poll() {
    Fake f;
    f.script.push_back(report(0, fw(E)));
    f.stop_before_poll = 1;
    const WatchResult r = run_watch(opts(5, 2), f.hooks(), "t");
    CHECK(r.stop == WatchStop::Interrupted && r.polls == 0 && !r.last_overall);
    CHECK(f.lines.size() == 1);  // only "stopped", with the injected timestamp
    if (!f.lines.empty()) CHECK(f.lines[0].find("2026-10-30T01:00:00Z") != std::string::npos);
}

void test_loop_output_failure_stops() {
    Fake f;
    for (int i = 0; i < 6; ++i) f.script.push_back(report(i, fw(i < 2 ? E : D)));
    f.fail_emit_at = 2;  // the change event
    const WatchResult r = run_watch(opts(6, 1), f.hooks(), "t");
    CHECK(r.stop == WatchStop::OutputFailed);
    CHECK(r.polls == 3);
    Fake g;
    g.script.push_back(report(0, fw(E)));
    g.fail_emit_at = 1;  // baseline
    CHECK(run_watch(opts(3, 1), g.hooks(), "t").stop == WatchStop::OutputFailed);
    Fake h;
    h.script.push_back(report(0, fw(E)));
    h.fail_emit_at = 2;  // closing line
    CHECK(run_watch(opts(1, 1), h.hooks(), "t").stop == WatchStop::OutputFailed);
}

void test_loop_exit_basis_is_last_poll() {
    Fake f;
    f.script.push_back(report(0, fw(E)));
    f.script.push_back(report(1, fw(U)));
    const WatchResult r = run_watch(opts(2, 2), f.hooks(), "t");
    CHECK(r.last_overall && *r.last_overall == Overall::Incomplete);
    CHECK(f.lines.size() == 2);  // one UNKNOWN poll is debounced: baseline + stopped
}

void test_loop_deterministic() {
    auto once = [] {
        Fake f;
        const State seq[] = {E, D, D, E, U, U, U, E, E, E};
        for (int i = 0; i < 10; ++i) f.script.push_back(report(i, fw(seq[i])));
        run_watch(opts(10, 2), f.hooks(), "t");
        std::string all;
        for (const auto& l : f.lines) all += l;
        return all;
    };
    CHECK(once() == once());
}

// --- args and rendering -------------------------------------------------------------------------

ParsedArgs parse(std::vector<std::string_view> a) { return parse_args(a); }

void test_args() {
    auto p = parse({"watch"});
    CHECK(p.command == Command::Watch && !p.json && p.interval_seconds == 30 && p.max_polls == 0 &&
          p.confirm_polls == 2);
    p = parse({"watch", "--json", "--interval", "5", "--max-polls", "10", "--confirm", "3"});
    CHECK(p.command == Command::Watch && p.json && p.interval_seconds == 5 && p.max_polls == 10 &&
          p.confirm_polls == 3);
    p = parse({"watch", "--max-polls", "1", "--interval", "3600", "--confirm", "10"});
    CHECK(p.command == Command::Watch && p.interval_seconds == 3600 && p.confirm_polls == 10);
    const std::vector<std::vector<std::string_view>> bad = {
        {"watch", "--interval"},
        {"watch", "--interval", "0"},
        {"watch", "--interval", "3601"},
        {"watch", "--interval", "-1"},
        {"watch", "--interval", "1.5"},
        {"watch", "--interval", "abc"},
        {"watch", "--interval", ""},
        {"watch", "--interval", "99999999999"},
        {"watch", "--interval", "1", "--interval", "2"},
        {"watch", "--max-polls", "0"},
        {"watch", "--max-polls", "1000001"},
        {"watch", "--confirm", "0"},
        {"watch", "--confirm", "11"},
        {"watch", "--json", "--json"},
        {"watch", "--bogus"},
        {"watch", "extra"},
        {"watch", "--interval", "--json"},
    };
    for (const auto& a : bad) {
        const ParsedArgs q = parse_args(a);
        CHECK(q.command == Command::Invalid && !q.error.empty());
    }
    // other commands do not accept watch flags
    CHECK(parse({"status", "--interval", "5"}).command == Command::Invalid);
    CHECK(usage_text("1").find("meta-sec watch") != std::string::npos);
}

void test_render_hostile_text() {
    WatchEvent e;
    e.check_id = "id\x1b[31m\n";
    e.observed_at_utc = utc_of(1);
    e.from = E;
    e.to = D;
    e.error_code = "bad\x07";
    const std::string t = render_watch_event_text(e);
    CHECK(t.find('\x1b') == std::string::npos && t.find('\x07') == std::string::npos);
    CHECK(t.find('\n') == t.size() - 1);
    const std::string j = render_watch_event_json(e);
    CHECK(j.find('\x1b') == std::string::npos && j.find('\n') == j.size() - 1);
}

int emit_ndjson() {
    Fake f;
    StatusReport base = report(0, fw(E));
    base.hostname = "a\"b\\c\n\xFF";
    f.script.push_back(base);
    const State seq[] = {E, D, D, U, U, E, E};
    for (int i = 1; i < 7; ++i) {
        StatusReport r = report(i, fw(seq[i]));
        r.checks[0].source = "src\"x\\";
        r.checks[0].evidence = {{"k\"", "v\n\\"}};
        f.script.push_back(r);
    }
    WatchOptions o = opts(7, 2);
    run_watch(o, f.hooks(), "9.9.9");
    for (const auto& l : f.lines) std::fputs(l.c_str(), stdout);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--emit-ndjson") return emit_ndjson();
    test_no_change();
    test_single_change_single_event();
    test_confirm_one_is_immediate();
    test_change_and_back_gives_two_events();
    test_flapping_is_suppressed();
    test_candidate_restarts_when_it_changes();
    test_transient_unknown_is_not_reported();
    test_persistent_unknown_is_lost_not_disabled();
    test_recovery_after_unknown();
    test_unobserved_to_not_supported_is_plain_change();
    test_unknown_in_baseline();
    test_added_and_removed_checks();
    test_duplicate_ids_first_wins();
    test_observe_before_baseline_sets_it();
    test_independent_checks_each_get_one_event();
    test_invariants_sweep();
    test_loop_one_change_one_alert();
    test_loop_no_change_only_baseline_and_stopped();
    test_loop_text_mode();
    test_loop_interrupted_in_wait();
    test_loop_interrupted_before_first_poll();
    test_loop_output_failure_stops();
    test_loop_exit_basis_is_last_poll();
    test_loop_deterministic();
    test_args();
    test_render_hostile_text();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
