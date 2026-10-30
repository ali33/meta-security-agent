// Dependency-free unit tests for the pure security core. Exit code 0 = all passed.
#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "core/cli.hpp"
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
    CHECK(json_escape("\xC0\xAF") == "\\ufffd\\ufffd");      // overlong
    CHECK(json_escape("\xED\xA0\x80") == "\\ufffd\\ufffd\\ufffd");  // surrogate
    CHECK(json_escape("\xE1\xBB") == "\\ufffd\\ufffd");      // truncated
    CHECK(json_escape("ok\xE1") == "ok\\ufffd");
}

// --- Overall / exit-code logic ----------------------------------------------------------------
CheckResult cr(State s, std::string err = {}) {
    CheckResult c;
    c.check_id = "x";
    c.state = s;
    c.error_code = std::move(err);
    return c;
}

void test_overall() {
    CHECK(compute_overall({}) == Overall::Incomplete);  // nothing observed is not OBSERVED
    CHECK(compute_overall({cr(State::Enabled), cr(State::Disabled), cr(State::Good)}) ==
          Overall::Observed);
    CHECK(compute_overall({cr(State::Enabled), cr(State::Unknown)}) == Overall::Incomplete);
    CHECK(compute_overall({cr(State::Enabled), cr(State::NotSupported)}) == Overall::Incomplete);
    CHECK(compute_overall({cr(State::Good), cr(State::NotMonitored)}) == Overall::Incomplete);
    CHECK(compute_overall({cr(State::Poor), cr(State::Snooze)}) == Overall::Observed);
    CHECK(exit_code_for(Overall::Observed) == 0);
    CHECK(exit_code_for(Overall::Incomplete) == 3);
    CHECK(kExitViolation == 1 && kExitError == 2);
}

// --- Failure classification: a failed call is never a positive state --------------------------
void test_failures() {
    CHECK(classify_failure(0x80004001u) == State::NotSupported);  // E_NOTIMPL
    CHECK(classify_failure(0x80040154u) == State::NotSupported);  // class not registered
    CHECK(classify_failure(0x8004100Eu) == State::NotSupported);  // WBEM invalid namespace
    CHECK(classify_failure(0x80070005u) == State::Unknown);       // access denied
    CHECK(classify_failure(0x80004005u) == State::Unknown);       // E_FAIL
    for (std::uint32_t hr : {0x80004005u, 0x80070005u, 0x80004001u, 0x8004100Eu, 0xDEADBEEFu, 0u}) {
        const CheckResult r = make_failure("id", "t", "src", hr);
        CHECK(r.state == State::Unknown || r.state == State::NotSupported);
        CHECK(!r.error_code.empty());
        CHECK(is_incomplete(r.state));
    }
    CHECK(hresult_code(0x80070005u) == "HRESULT:0x80070005");
    CHECK(wsc_health_to_state(0) == State::Good);
    CHECK(wsc_health_to_state(1) == State::NotMonitored);
    CHECK(wsc_health_to_state(2) == State::Poor);
    CHECK(wsc_health_to_state(3) == State::Snooze);
    CHECK(wsc_health_to_state(99) == State::Unknown);
    CHECK(wsc_health_to_state(-1) == State::Unknown);
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
    CHECK(j.find("PROTECTED") == std::string::npos);

    const std::string t = render_status_text(sample(), "0.1.0");
    CHECK(t.find("Overall: INCOMPLETE") != std::string::npos);
    CHECK(t.find("not an antivirus protection verdict") != std::string::npos);
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
    CHECK(usage_text("1.2.3").find("1.2.3") != std::string::npos);
}

}  // namespace

int main() {
    test_json_escape();
    test_overall();
    test_failures();
    test_render();
    test_args();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
