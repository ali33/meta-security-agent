// Dependency-free unit tests for the pure security core. Exit code 0 = all passed.
// `metasec_tests --emit-json` prints a hostile report instead; CTest parses it with
// CMake's own JSON parser (tests/json_roundtrip.cmake) as an independent validity check.
#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "core/cli.hpp"
#include "core/interpret.hpp"
#include "core/json.hpp"
#include "core/render.hpp"
#include "core/types.hpp"

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

ParsedArgs parse(std::vector<std::string_view> a) { return parse_args(a); }

static_assert(kExitOk == 0 && kExitViolation == 1 && kExitError == 2 && kExitIncomplete == 3);

// --- JSON escaping -------------------------------------------------------------------------
void test_json_escape() {
    CHECK(json_escape("plain") == "plain");
    CHECK(json_escape("a\"b") == "a\\\"b");
    CHECK(json_escape("a\\b") == "a\\\\b");
    CHECK(json_escape("l1\nl2\r\t") == "l1\\nl2\\r\\t");
    CHECK(json_escape(std::string("x\0y", 3)) == "x\\u0000y");
    CHECK(json_escape("\x01\x1f") == "\\u0001\\u001f");
    CHECK(json_escape("\x7f") == "\\u007f");
    // valid UTF-8 passes through untouched (Vietnamese, emoji)
    CHECK(json_escape("Nguy\xE1\xBB\x85n") == "Nguy\xE1\xBB\x85n");
    CHECK(json_escape("\xF0\x9F\x98\x80") == "\xF0\x9F\x98\x80");
    // invalid UTF-8 becomes U+FFFD, never raw bytes
    CHECK(json_escape("\xFF") == "\\ufffd");
    CHECK(json_escape("\xC0\xAF") == "\\ufffd\\ufffd");             // overlong
    CHECK(json_escape("\xED\xA0\x80") == "\\ufffd\\ufffd\\ufffd");  // surrogate
    CHECK(json_escape("\xE1\xBB") == "\\ufffd\\ufffd");             // truncated
    CHECK(json_escape("ok\xE1") == "ok\\ufffd");
    // boundaries
    CHECK(json_escape("\xF4\x8F\xBF\xBF") == "\xF4\x8F\xBF\xBF");  // U+10FFFF is valid
    CHECK(json_escape("\xF4\x90\x80\x80") == "\\ufffd\\ufffd\\ufffd\\ufffd");  // > U+10FFFF
    CHECK(json_escape("\xF5\x80\x80\x80") == "\\ufffd\\ufffd\\ufffd\\ufffd");
    CHECK(json_escape("\xC1\x80") == "\\ufffd\\ufffd");  // overlong
    CHECK(json_escape("\xE0\xA0\x80") == "\xE0\xA0\x80");  // U+0800 is valid
    CHECK(json_escape("\xE0\x9F\xBF") == "\\ufffd\\ufffd\\ufffd");  // overlong
    CHECK(json_escape("\x80") == "\\ufffd");                         // lone continuation
    CHECK(json_escape("\xEF\xBF\xBD") == "\xEF\xBF\xBD");            // U+FFFD itself
}

// --- Overall / posture / exit-code logic -------------------------------------------------------
CheckResult cr(State s, std::string err = {}) {
    CheckResult c;
    c.check_id = "x";
    c.state = s;
    c.error_code = std::move(err);
    return c;
}

void test_overall() {
    CHECK(compute_overall({}) == Overall::Incomplete);  // nothing observed is not OBSERVED
    CHECK(compute_overall({cr(State::Enabled), cr(State::Good)}) == Overall::Observed);
    CHECK(compute_overall({cr(State::Enabled), cr(State::Unknown)}) == Overall::Incomplete);
    CHECK(compute_overall({cr(State::Enabled), cr(State::NotSupported)}) == Overall::Incomplete);
    CHECK(compute_overall({cr(State::Good), cr(State::NotMonitored)}) == Overall::Incomplete);
    // observed-but-bad is flagged, never plain OBSERVED; exit stays 0 (status is not audit)
    CHECK(compute_overall({cr(State::Poor), cr(State::Snooze)}) == Overall::ObservedWithIssues);
    CHECK(compute_overall({cr(State::Enabled), cr(State::Disabled)}) == Overall::ObservedWithIssues);
    CHECK(compute_overall({cr(State::Enabled), cr(State::Passive)}) == Overall::Observed);
    CHECK(compute_overall({cr(State::Disabled), cr(State::Unknown)}) == Overall::Incomplete);
    CHECK(exit_code_for(Overall::Observed) == 0);
    CHECK(exit_code_for(Overall::ObservedWithIssues) == 0);
    CHECK(exit_code_for(Overall::Incomplete) == 3);

    CHECK(posture_of(State::Disabled) == Posture::Attention);
    CHECK(posture_of(State::Poor) == Posture::Attention);
    CHECK(posture_of(State::Enabled) == Posture::Ok);
    CHECK(posture_of(State::Good) == Posture::Ok);
    CHECK(posture_of(State::Passive) == Posture::NotApplicable);
    CHECK(posture_of(State::Unknown) == Posture::Unknown);
    CHECK(posture_of(State::NotSupported) == Posture::Unknown);

    CheckResult a = cr(State::Disabled);
    a.check_id = "a";
    CheckResult b = cr(State::Enabled);
    b.check_id = "b";
    const auto ids = attention_ids({a, b});
    CHECK(ids.size() == 1 && ids[0] == "a");
}

// --- Failure classification: a failed call is never a positive state --------------------------
void test_failures() {
    CHECK(classify_failure(0x80004001u) == State::NotSupported);  // E_NOTIMPL
    CHECK(classify_failure(0x80040154u) == State::NotSupported);  // class not registered
    CHECK(classify_failure(0x8004100Eu) == State::NotSupported);  // WBEM invalid namespace
    CHECK(classify_failure(0x80041010u) == State::NotSupported);  // WBEM invalid class
    CHECK(classify_failure(0x80070032u) == State::NotSupported);  // ERROR_NOT_SUPPORTED
    CHECK(classify_failure(0x80004002u) == State::NotSupported);  // E_NOINTERFACE
    CHECK(classify_failure(0x80070426u) == State::NotSupported);  // service does not exist
    CHECK(classify_failure(0x80070425u) == State::Unknown);       // service not active: transient
    CHECK(classify_failure(0x80070005u) == State::Unknown);       // access denied
    CHECK(classify_failure(0x80004005u) == State::Unknown);       // E_FAIL
    for (std::uint32_t hr : {0x80004005u, 0x80070005u, 0x80004001u, 0x8004100Eu, 0xDEADBEEFu, 0u}) {
        const CheckResult r = make_failure("id", "t", "src", hr);
        CHECK(r.state == State::Unknown || r.state == State::NotSupported);
        CHECK(!r.error_code.empty());
        CHECK(is_incomplete(r.state));
    }
    const CheckResult t = make_failure_code("id", "t", "s", State::Enabled, "TIMEOUT");
    CHECK(t.state == State::Unknown && t.error_code == "TIMEOUT");  // positive coerced away
    CHECK(make_failure_code("id", "t", "s", State::NotSupported, "").error_code == "UNSPECIFIED");
    CHECK(hresult_code(0x80070005u) == "HRESULT:0x80070005");
    CHECK(wsc_health_to_state(0) == State::Good);
    CHECK(wsc_health_to_state(1) == State::NotMonitored);
    CHECK(wsc_health_to_state(2) == State::Poor);
    CHECK(wsc_health_to_state(3) == State::Snooze);
    CHECK(wsc_health_to_state(99) == State::Unknown);
    CHECK(wsc_health_to_state(-1) == State::Unknown);
}

// --- Provider interpretation with fakes ---------------------------------------------------------
const CheckResult* find(const std::vector<CheckResult>& v, const char* id) {
    for (const auto& c : v)
        if (c.check_id == id) return &c;
    return nullptr;
}

void test_interpret() {
    const std::string now = "t";
    CHECK(interpret_firewall_profile(kIdFwPublic, now, 0, true).state == State::Enabled);
    CHECK(interpret_firewall_profile(kIdFwPublic, now, 0, false).state == State::Disabled);
    {
        // failed call: the `enabled` value must be ignored
        const auto r = interpret_firewall_profile(kIdFwPublic, now, static_cast<std::int32_t>(0x80070005u), true);
        CHECK(r.state == State::Unknown && r.error_code == "HRESULT:0x80070005");
    }
    CHECK(interpret_wsc(now, 0, 0).state == State::Good);
    CHECK(interpret_wsc(now, 0, 2).state == State::Poor);
    CHECK(interpret_wsc(now, static_cast<std::int32_t>(0x80004001u), 0).state == State::NotSupported);
    CHECK(interpret_wsc(now, static_cast<std::int32_t>(0x80004005u), 0).state == State::Unknown);

    // Normal mode: raw flags decide
    DefenderRaw n;
    n.running_mode = "Normal";
    n.antivirus_enabled = true;
    n.realtime_enabled = true;
    n.signature_age_days = 3;
    auto d = interpret_defender(n, State::Good, now);
    CHECK(d.size() == 2);
    CHECK(find(d, kIdDefenderAv)->state == State::Enabled);
    CHECK(find(d, kIdDefenderRt)->state == State::Enabled);
    CHECK(find(d, kIdDefenderAv)->evidence.back().first == "signature_age_days");
    n.realtime_enabled = false;
    d = interpret_defender(n, State::Good, now);
    CHECK(find(d, kIdDefenderRt)->state == State::Disabled);

    // missing flag => UNKNOWN with a code, never a positive state
    DefenderRaw m;
    m.running_mode = "Normal";
    d = interpret_defender(m, State::Good, now);
    CHECK(find(d, kIdDefenderAv)->state == State::Unknown);
    CHECK(find(d, kIdDefenderAv)->error_code == "PROPERTY_UNAVAILABLE:AntivirusEnabled");

    // Passive: AntivirusEnabled may be TRUE but must not be reported ENABLED
    DefenderRaw p;
    p.running_mode = "Passive";
    p.antivirus_enabled = true;
    p.realtime_enabled = true;
    d = interpret_defender(p, State::Good, now);
    CHECK(find(d, kIdDefenderAv)->state == State::Passive);
    CHECK(find(d, kIdDefenderRt)->state == State::Passive);
    p.running_mode = "SxS Passive Mode";
    CHECK(interpret_defender(p, State::Poor, now)[0].state == State::Passive);

    // Not running: PASSIVE only if WSC confirms another healthy AV, else DISABLED
    DefenderRaw nr;
    nr.running_mode = "Not running";
    nr.antivirus_enabled = false;
    nr.realtime_enabled = false;
    nr.signature_age_days = 65535;  // sentinel: omitted from evidence
    d = interpret_defender(nr, State::Good, now);
    CHECK(find(d, kIdDefenderAv)->state == State::Passive);
    CHECK(find(d, kIdDefenderRt)->state == State::Passive);
    for (const auto& kv : find(d, kIdDefenderAv)->evidence) CHECK(kv.first != "signature_age_days");
    for (State w : {State::Poor, State::NotMonitored, State::Unknown, State::NotSupported}) {
        d = interpret_defender(nr, w, now);
        CHECK(find(d, kIdDefenderAv)->state == State::Disabled);
        CHECK(find(d, kIdDefenderRt)->state == State::Disabled);
    }
    // unreadable flags but known mode: resolved from the mode, no leftover error
    DefenderRaw nrm;
    nrm.running_mode = "Not running";
    d = interpret_defender(nrm, State::Good, now);
    CHECK(find(d, kIdDefenderAv)->state == State::Passive && find(d, kIdDefenderAv)->error_code.empty());

    // no mode at all and no flags: UNKNOWN
    d = interpret_defender(DefenderRaw{}, State::Good, now);
    CHECK(d[0].state == State::Unknown && d[1].state == State::Unknown);

    // whole-call failures
    d = defender_failure(now, State::Unknown, "TIMEOUT");
    CHECK(d.size() == 2 && d[0].state == State::Unknown && d[0].error_code == "TIMEOUT");
    d = defender_failure(now, State::NotSupported, "HRESULT:0x8004100E");
    CHECK(d[1].state == State::NotSupported);
}

// --- Rendering ----------------------------------------------------------------------------
StatusReport sample() {
    StatusReport r;
    r.hostname = "HOST\"1";
    r.observed_at_utc = "2026-10-30T12:34:56Z";
    r.platform = {"windows", "10.0.26200", "client"};
    CheckResult a;
    a.check_id = "firewall.public";
    a.observed_at_utc = r.observed_at_utc;
    a.state = State::Enabled;
    a.source = "INetFwPolicy2";
    r.checks.push_back(a);
    CheckResult b = make_failure("antivirus.defender.antivirus", r.observed_at_utc, "WMI", 0x8004100Eu);
    b.evidence.emplace_back("note", "line1\nline2 \"q\"");
    r.checks.push_back(b);
    return r;
}

void test_render() {
    CHECK(format_utc(std::chrono::system_clock::time_point{std::chrono::seconds{0}}) ==
          "1970-01-01T00:00:00Z");
    CHECK(format_utc(std::chrono::system_clock::time_point{std::chrono::seconds{1761827696}}) ==
          "2025-10-30T12:34:56Z");

    const std::string j = render_status_json(sample(), "0.1.0");
    CHECK(j.back() == '\n');
    CHECK(j.find('\n') == j.size() - 1);  // single line
    CHECK(j.find("\"schema_version\":1,") != std::string::npos);
    CHECK(j.find("\"hostname\":\"HOST\\\"1\"") != std::string::npos);
    CHECK(j.find("\"state\":\"ENABLED\"") != std::string::npos);
    CHECK(j.find("\"state\":\"NOT_SUPPORTED\"") != std::string::npos);
    CHECK(j.find("\"error_code\":\"HRESULT:0x8004100E\"") != std::string::npos);
    CHECK(j.find("\"note\":\"line1\\nline2 \\\"q\\\"\"") != std::string::npos);
    CHECK(j.find("\"overall\":\"INCOMPLETE\"") != std::string::npos);
    CHECK(j.find("\"posture\":\"OK\"") != std::string::npos);
    CHECK(j.find("\"posture\":\"UNKNOWN\"") != std::string::npos);
    CHECK(j.find("\"attention\":[]") != std::string::npos);
    CHECK(j.find("PROTECTED") == std::string::npos);

    StatusReport bad = sample();
    bad.checks[0].state = State::Disabled;
    const std::string jb = render_status_json(bad, "0.1.0");
    CHECK(jb.find("\"attention\":[\"firewall.public\"]") != std::string::npos);
    CHECK(jb.find("\"posture\":\"ATTENTION\"") != std::string::npos);
    CHECK(render_status_text(bad, "0.1.0").find("ATTENTION") != std::string::npos);

    const std::string t = render_status_text(sample(), "0.1.0");
    CHECK(t.find("Overall: INCOMPLETE") != std::string::npos);
    CHECK(t.find("not an antivirus protection verdict") != std::string::npos);

    // identifiers and evidence keys are escaped as well
    StatusReport r;
    CheckResult c;
    c.check_id = "i\"d";
    c.state = State::Enabled;
    c.evidence.emplace_back("k\"ey\\", "v");
    r.checks.push_back(c);
    const std::string je = render_status_json(r, "1");
    CHECK(je.find("\"k\\\"ey\\\\\":\"v\"") != std::string::npos);
    CHECK(je.find("\"check_id\":\"i\\\"d\"") != std::string::npos);
}

// --- Argument parsing ---------------------------------------------------------------------
void test_args() {
    CHECK(parse({"--help"}).command == Command::Help);
    CHECK(parse({"-h"}).command == Command::Help);
    CHECK(parse({"--version"}).command == Command::Version);
    CHECK(parse({"status"}).command == Command::Status);
    CHECK(!parse({"status"}).json);
    CHECK(parse({"status", "--json"}).command == Command::Status);
    CHECK(parse({"status", "--json"}).json);

    CHECK(parse({}).command == Command::Invalid);
    CHECK(parse({"bogus"}).command == Command::Invalid);
    CHECK(parse({"status", "--bogus"}).command == Command::Invalid);
    CHECK(parse({"status", "--json", "--json"}).command == Command::Invalid);
    CHECK(parse({"status", "--json", "extra"}).command == Command::Invalid);
    CHECK(parse({"--help", "status"}).command == Command::Invalid);
    CHECK(parse({"--json"}).command == Command::Invalid);
    CHECK(parse({"STATUS"}).command == Command::Invalid);  // case-sensitive
    CHECK(!parse({"bogus"}).error.empty());

    // hostile argument cannot inject control characters into the diagnostic
    const std::string msg = parse({"\x1b[31mred\n"}).error;
    CHECK(msg.find('\x1b') == std::string::npos && msg.find('\n') == std::string::npos);
    CHECK(sanitize_for_display(std::string(500, 'a')).size() < 100);
    // truncation never splits a UTF-8 character; C1 controls are removed
    std::string long_vi;
    for (int i = 0; i < 100; ++i) long_vi += "\xE1\xBB\x85";
    const std::string tr = sanitize_for_display(long_vi);
    CHECK(tr.size() <= 70);
    CHECK(json_escape(tr).find("\\ufffd") == std::string::npos);  // still valid UTF-8
    CHECK(sanitize_for_display("a\xC2\x9B" "b") == "a?b");
    CHECK(usage_text("1.2.3").find("1.2.3") != std::string::npos);
}

int emit_hostile_json() {
    StatusReport r;
    r.hostname = std::string("a\"b\\c\nd\te\x01") + "\xFF" + "end";
    r.observed_at_utc = "2026-10-30T00:00:00Z";
    r.platform = {"windows", "10.0.1", "client"};
    CheckResult c = make_failure("x\"y", r.observed_at_utc, "src\\", 0x80004005u);
    c.evidence.emplace_back("k\"ey", "v\nal");
    r.checks.push_back(c);
    const std::string j = render_status_json(r, "1");
    std::fwrite(j.data(), 1, j.size(), stdout);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--emit-json") return emit_hostile_json();
    test_json_escape();
    test_overall();
    test_failures();
    test_interpret();
    test_render();
    test_args();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
