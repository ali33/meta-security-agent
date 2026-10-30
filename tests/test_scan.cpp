// Deterministic tests for MVP-3 (scan): eligibility gate, approval state machine, outcome
// interpretation, and the orchestration with fake hooks. The key property under test is that the
// side-effect hook (start_quick_scan) is NEVER called unless the gate AND a valid typed approval
// both pass. No test here touches the OS or can start a real scan.
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "core/cli.hpp"
#include "core/scan.hpp"

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

constexpr long long kT1 = 1793363696;  // 2026-10-30T12:34:56Z

DefenderScanObservation def_obs(const char* mode, ScanTimes t = {}) {
    DefenderScanObservation o;
    o.obs = Obs::Observed;
    if (mode) o.running_mode = mode;
    o.times = t;
    return o;
}

AvProductsObservation av_with(std::vector<AvProduct> p) {
    AvProductsObservation a;
    a.obs = Obs::Observed;
    a.products = std::move(p);
    return a;
}

// ---- datetime ----
void test_datetime() {
    CHECK(parse_cim_datetime("20261030123456.000000+000") == kT1);
    CHECK(parse_cim_datetime("20261030123456.123456+000") == kT1);  // fraction ignored
    CHECK(parse_cim_datetime("19700101000000.000000+000") == 0);
    CHECK(parse_cim_datetime("20240229235959.000000+000") == 1709251199);  // leap day
    CHECK(parse_cim_datetime("20261030193456.000000+420") == kT1);         // local 19:34 at UTC+7
    CHECK(parse_cim_datetime("20261030053456.000000-420") == kT1);         // local 05:34 at UTC-7
    CHECK(!parse_cim_datetime(""));
    CHECK(!parse_cim_datetime("20261030123456"));
    CHECK(!parse_cim_datetime("20261030123456.000000*000"));
    CHECK(!parse_cim_datetime("2026103012345*.000000+000"));  // wildcard
    CHECK(!parse_cim_datetime("20261330123456.000000+000"));  // month 13
    CHECK(!parse_cim_datetime("20260230123456.000000+000"));  // 30 Feb
    CHECK(!parse_cim_datetime("20230229123456.000000+000"));  // not a leap year
    CHECK(!parse_cim_datetime("20261030243456.000000+000"));  // hour 24
    CHECK(!parse_cim_datetime("20261030123456.000000+999"));  // offset out of range
    CHECK(!parse_cim_datetime("16010101000000.000000+000"));  // before 1970
    CHECK(!parse_cim_datetime("2026-10-30T12:34:56Z"));
    CHECK(format_epoch_utc(kT1) == "2026-10-30T12:34:56Z");
}

// ---- gate ----
void test_gate() {
    const AvProductsObservation none = av_with({});
    CHECK(evaluate_scan_gate(def_obs("Normal"), none).allowed);
    CHECK(evaluate_scan_gate(def_obs("Normal"), none).code == "DEFENDER_NORMAL");

    // Everything that is not exactly "Normal" is refused (fail closed), with a stable code.
    struct Case { const char* mode; const char* code; };
    const Case cases[] = {
        {"Passive", "MODE_PASSIVE"},       {"Passive mode", "MODE_PASSIVE"},
        {"SxS Passive Mode", "MODE_PASSIVE"}, {"EDR Block Mode", "MODE_PASSIVE"},
        {"Not running", "MODE_NOT_RUNNING"},
        {"", "MODE_UNRECOGNIZED"},         {"normal", "MODE_UNRECOGNIZED"},
        {"NORMAL", "MODE_UNRECOGNIZED"},   {"Normal ", "MODE_UNRECOGNIZED"},
        {"Normal\n", "MODE_UNRECOGNIZED"}, {"Quantum", "MODE_UNRECOGNIZED"},
    };
    for (const auto& c : cases) {
        const ScanGate g = evaluate_scan_gate(def_obs(c.mode), none);
        CHECK(!g.allowed);
        CHECK(g.code == c.code);
        CHECK(!g.message.empty());
    }
    // AMRunningMode absent.
    CHECK(!evaluate_scan_gate(def_obs(nullptr), none).allowed);
    CHECK(evaluate_scan_gate(def_obs(nullptr), none).code == "MODE_MISSING");

    // Defender namespace unavailable / failed. Even if a mode string slipped through, it is ignored.
    DefenderScanObservation ns;
    ns.obs = Obs::NotSupported;
    ns.error_code = "HRESULT:0x8004100E";
    ns.running_mode = "Normal";
    CHECK(!evaluate_scan_gate(ns, none).allowed);
    CHECK(evaluate_scan_gate(ns, none).code == "DEFENDER_NOT_SUPPORTED");
    DefenderScanObservation un;
    un.obs = Obs::Unknown;
    un.error_code = "TIMEOUT";
    un.running_mode = "Normal";
    CHECK(!evaluate_scan_gate(un, none).allowed);
    CHECK(evaluate_scan_gate(un, none).code == "DEFENDER_UNAVAILABLE");
    CHECK(evaluate_scan_gate(un, none).message.find("TIMEOUT") != std::string::npos);

    // Names the AV that is actually protecting the machine; other products are not named.
    const AvProductsObservation av = av_with({{"Bitdefender", 0x061000}, {"Old AV", 0x060000}});
    const ScanGate g = evaluate_scan_gate(def_obs("Not running"), av);
    CHECK(!g.allowed);
    CHECK(g.protecting_av.size() == 1 && g.protecting_av[0] == "Bitdefender");
    CHECK(g.message.find("Bitdefender") != std::string::npos);
    CHECK(g.message.find("Old AV") == std::string::npos);
    // AV list unobservable: still refused, message says so honestly.
    AvProductsObservation bad;
    bad.obs = Obs::NotSupported;
    const ScanGate g2 = evaluate_scan_gate(def_obs("Passive"), bad);
    CHECK(!g2.allowed && g2.protecting_av.empty());
    CHECK(g2.message.find("No other active antivirus") != std::string::npos);
    // Vendor strings are untrusted: control characters never reach the message.
    const ScanGate g3 = evaluate_scan_gate(def_obs("Passive"), av_with({{"Evil\x1b[2J\nAV", 0x061000}}));
    CHECK(g3.message.find('\x1b') == std::string::npos && g3.message.find('\n') == std::string::npos);
    const ScanGate g4 = evaluate_scan_gate(def_obs("Pass\x1b\nive"), none);
    CHECK(g4.message.find('\x1b') == std::string::npos && g4.running_mode.find('\x1b') == std::string::npos);
}

// ---- approval ----
ApprovalInput typed(const std::string& line) {
    ApprovalInput i;
    i.input_is_console = true;
    i.output_is_console = true;
    i.read = ReadStatus::Ok;
    i.line = line;
    return i;
}

void test_approval() {
    CHECK(evaluate_approval(typed("START QUICK SCAN\r\n")).approved);
    CHECK(evaluate_approval(typed("START QUICK SCAN\n")).approved);
    CHECK(evaluate_approval(typed("START QUICK SCAN")).approved);
    CHECK(evaluate_approval(typed("START QUICK SCAN")).reason == "APPROVED");

    const char* wrong[] = {"", "\r\n", "y", "yes", "Y\r\n", "start quick scan", "START QUICK SCAN ", " START QUICK SCAN",
                           "START QUICK SCAN\r\nSTART QUICK SCAN", "START QUICK SCANX", "START QUICK", "START  QUICK SCAN",
                           "\x01", "START QUICK SCAN\x1a", "START QUICK SCAN\t"};
    for (const char* w : wrong) {
        const ApprovalDecision d = evaluate_approval(typed(w));
        CHECK(!d.approved);
        CHECK(d.reason == "WRONG_CONFIRMATION");
    }

    // The correct phrase is irrelevant when the input is not a human at a console.
    ApprovalInput piped = typed("START QUICK SCAN\r\n");
    piped.input_is_console = false;
    CHECK(!evaluate_approval(piped).approved && evaluate_approval(piped).reason == "NOT_A_CONSOLE");
    ApprovalInput blind = typed("START QUICK SCAN\r\n");
    blind.output_is_console = false;
    CHECK(!evaluate_approval(blind).approved && evaluate_approval(blind).reason == "NO_VISIBLE_PROMPT");
    ApprovalInput neither = typed("START QUICK SCAN\r\n");
    neither.input_is_console = neither.output_is_console = false;
    CHECK(!evaluate_approval(neither).approved);

    // Read failures can never approve, even with the phrase left in the buffer.
    for (ReadStatus s : {ReadStatus::Eof, ReadStatus::Error, ReadStatus::Interrupted}) {
        ApprovalInput i = typed("START QUICK SCAN\r\n");
        i.read = s;
        CHECK(!evaluate_approval(i).approved);
    }
    ApprovalInput eof;  // default-constructed = nothing happened
    CHECK(!evaluate_approval(eof).approved);
    CHECK(!evaluate_approval(ApprovalInput{}).approved);

    const std::string p = approval_prompt_text("HOST\\user", "Normal", true);
    CHECK(p.find("START QUICK SCAN") != std::string::npos);
    CHECK(p.find("HOST\\user") != std::string::npos);
    CHECK(p.find("not elevated") == std::string::npos);
    CHECK(approval_prompt_text("u", "Normal", false).find("not elevated") != std::string::npos);
    CHECK(approval_prompt_text("u\x1b[31m", "Normal", true).find('\x1b') == std::string::npos);
}

// ---- outcome interpretation ----
constexpr std::int32_t kAccessDenied = static_cast<std::int32_t>(0x80070005u);
constexpr std::int32_t kWbemAccessDenied = static_cast<std::int32_t>(0x80041003u);
constexpr std::int32_t kOtherFail = static_cast<std::int32_t>(0x80041001u);

void test_outcome() {
    const ScanTimes old_scan{kT1 - 86400, kT1 - 86000};
    const ScanTimes new_scan{kT1, kT1 + 120};
    const ScanTimes running{kT1, kT1 - 86000};  // started, end time still the old one
    StartResult ok;  // exec ok, finished, status ok, no return value

    CHECK(new_scan_visible(old_scan, new_scan));
    CHECK(!new_scan_visible(old_scan, old_scan));
    CHECK(!new_scan_visible(old_scan, std::nullopt));
    CHECK(new_scan_visible(ScanTimes{}, new_scan));  // never scanned before
    CHECK(!new_scan_visible(old_scan, ScanTimes{}));

    CHECK(interpret_scan_outcome(ok, old_scan, new_scan) == ScanStatus::Completed);
    CHECK(interpret_scan_outcome(ok, ScanTimes{}, new_scan) == ScanStatus::Completed);
    StartResult rv0 = ok;
    rv0.return_value = 0;
    CHECK(interpret_scan_outcome(rv0, old_scan, new_scan) == ScanStatus::Completed);

    // Success reported by the API but no new scan visible: never claimed as done.
    CHECK(interpret_scan_outcome(ok, old_scan, old_scan) == ScanStatus::NotConfirmed);
    CHECK(interpret_scan_outcome(ok, old_scan, std::nullopt) == ScanStatus::NotConfirmed);
    // New scan visible but no completion time yet.
    CHECK(interpret_scan_outcome(ok, old_scan, running) == ScanStatus::StartedNotCompleted);

    // Errors: access denied is a permission error; everything else is a failure. Never success.
    for (std::int32_t hr : {kAccessDenied, kWbemAccessDenied}) {
        StartResult a = ok;
        a.exec_hr = hr;
        CHECK(interpret_scan_outcome(a, old_scan, new_scan) == ScanStatus::AccessDenied);  // even if a stale scan looks new
        StartResult b = ok;
        b.status_hr = hr;
        CHECK(interpret_scan_outcome(b, old_scan, new_scan) == ScanStatus::AccessDenied);
    }
    StartResult f1 = ok;
    f1.exec_hr = kOtherFail;
    CHECK(interpret_scan_outcome(f1, old_scan, new_scan) == ScanStatus::StartFailed);
    StartResult f2 = ok;
    f2.status_hr = kOtherFail;
    CHECK(interpret_scan_outcome(f2, old_scan, new_scan) == ScanStatus::StartFailed);
    StartResult f3 = ok;
    f3.return_value = 5;
    CHECK(interpret_scan_outcome(f3, old_scan, new_scan) == ScanStatus::StartFailed);

    // Timeout / Ctrl+C: honest "started but not seen to finish", or not confirmed.
    for (WaitEnd w : {WaitEnd::TimedOut, WaitEnd::Interrupted}) {
        StartResult t = ok;
        t.wait = w;
        CHECK(interpret_scan_outcome(t, old_scan, running) == ScanStatus::StartedNotCompleted);
        CHECK(interpret_scan_outcome(t, old_scan, new_scan) == ScanStatus::StartedNotCompleted);  // never Completed
        CHECK(interpret_scan_outcome(t, old_scan, old_scan) == ScanStatus::NotConfirmed);
    }

    // Exit-code contract.
    CHECK(scan_exit_code(ScanStatus::Completed) == 0);
    CHECK(scan_exit_code(ScanStatus::DryRunWouldProceed) == 0);
    CHECK(scan_exit_code(ScanStatus::RefusedNotApplicable) == 4);
    CHECK(scan_exit_code(ScanStatus::RefusedNotApproved) == 4);
    CHECK(scan_exit_code(ScanStatus::AccessDenied) == 2);
    CHECK(scan_exit_code(ScanStatus::StartFailed) == 2);
    CHECK(scan_exit_code(ScanStatus::StartedNotCompleted) == 3);
    CHECK(scan_exit_code(ScanStatus::NotConfirmed) == 3);
}

// ---- orchestration with fakes ----
struct Fake {
    std::vector<DefenderScanObservation> defender;  // consumed in order; the last repeats
    AvProductsObservation av = av_with({});
    ApprovalInput approval = typed("START QUICK SCAN\r\n");
    StartResult start;
    bool elevated = true;
    int observe_calls = 0, ask_calls = 0, start_calls = 0, start_timeout = 0;
    std::string last_prompt;
    int clock = 0;

    ScanHooks hooks() {
        ScanHooks h;
        h.observe_defender = [this] {
            const std::size_t i = std::min<std::size_t>(static_cast<std::size_t>(observe_calls++), defender.size() - 1);
            return defender[i];
        };
        h.observe_av = [this] { return av; };
        h.ask_approval = [this](const std::string& p) {
            ++ask_calls;
            last_prompt = p;
            return approval;
        };
        h.actor = [] { return std::string("LAB\\tester"); };
        h.elevated = [this] { return elevated; };
        h.start_quick_scan = [this](int t) {
            ++start_calls;
            start_timeout = t;
            return start;
        };
        h.now_utc = [this] { return std::string("2026-10-30T00:00:0") + std::to_string(clock++ % 10) + "Z"; };
        return h;
    }
};

const ScanTimes kOld{kT1 - 86400, kT1 - 86000};
const ScanTimes kNew{kT1, kT1 + 120};

void test_run_happy_path() {
    Fake f;
    f.defender = {def_obs("Normal", kOld), def_obs("Normal", kOld), def_obs("Normal", kNew)};
    const ScanReport r = run_scan({}, f.hooks());
    CHECK(r.status == ScanStatus::Completed);
    CHECK(f.ask_calls == 1 && f.start_calls == 1);
    CHECK(f.start_timeout == kScanWaitSeconds);
    CHECK(r.approval.approved && r.approval.reason == "APPROVED");
    CHECK(r.actor == "LAB\\tester" && !r.approved_at_utc.empty());
    CHECK(r.new_scan_confirmed && r.start_attempted);
    CHECK(f.last_prompt.find("LAB\\tester") != std::string::npos);
    CHECK(f.last_prompt.find("START QUICK SCAN") != std::string::npos);
    CHECK(scan_exit_code(r.status) == 0);
    const std::string j = render_scan_json(r, "9.9.9");
    CHECK(j.find("\"status\":\"COMPLETED\"") != std::string::npos);
    CHECK(j.find("\"actor\":\"LAB\\\\tester\"") != std::string::npos);
    CHECK(j.find("\"granted\":true") != std::string::npos);
    CHECK(j.find("\"new_scan_confirmed\":true") != std::string::npos);
    CHECK(j.find("\"quick_scan_start_utc\":\"2026-10-30T12:34:56Z\"") != std::string::npos);
    CHECK(j.back() == '\n' && j.find('\n') == j.size() - 1);  // one line
}

void test_run_dry_run_never_asks_or_starts() {
    Fake f;
    f.defender = {def_obs("Normal", kOld)};
    ScanOptions o;
    o.dry_run = true;
    const ScanReport r = run_scan(o, f.hooks());
    CHECK(r.status == ScanStatus::DryRunWouldProceed && r.dry_run);
    CHECK(f.ask_calls == 0 && f.start_calls == 0 && !r.start_attempted && !r.approval_asked);
    CHECK(scan_exit_code(r.status) == 0);
    // Dry run on a machine where the scan would be refused says so (exit 4) and still does nothing.
    Fake g;
    g.defender = {def_obs("Passive")};
    const ScanReport r2 = run_scan(o, g.hooks());
    CHECK(r2.status == ScanStatus::RefusedNotApplicable && g.start_calls == 0 && g.ask_calls == 0);
    CHECK(render_scan_text(r, "1").find("DRY RUN") != std::string::npos);
}

void test_run_gate_refusal_never_asks_or_starts() {
    for (const char* mode : {"Passive", "Not running", "SxS Passive Mode", "EDR Block Mode", "", "normal", "x"}) {
        Fake f;
        f.defender = {def_obs(mode)};
        const ScanReport r = run_scan({}, f.hooks());
        CHECK(r.status == ScanStatus::RefusedNotApplicable);
        CHECK(f.ask_calls == 0 && f.start_calls == 0);
        CHECK(!r.start_attempted && !r.approval_asked);
        CHECK(scan_exit_code(r.status) == 4);
    }
    Fake u;
    DefenderScanObservation bad;
    bad.obs = Obs::Unknown;
    bad.error_code = "HRESULT:0x80041003";
    u.defender = {bad};
    CHECK(run_scan({}, u.hooks()).status == ScanStatus::RefusedNotApplicable && u.start_calls == 0 && u.ask_calls == 0);
}

void test_run_approval_refusals_never_start() {
    struct Case { ApprovalInput in; const char* reason; };
    ApprovalInput not_console = typed("START QUICK SCAN\r\n");
    not_console.input_is_console = false;
    ApprovalInput no_prompt = typed("START QUICK SCAN\r\n");
    no_prompt.output_is_console = false;
    ApprovalInput eof;
    ApprovalInput intr = typed("START QUICK SCAN\r\n");
    intr.read = ReadStatus::Interrupted;
    const Case cases[] = {{not_console, "NOT_A_CONSOLE"}, {no_prompt, "NO_VISIBLE_PROMPT"}, {eof, "NOT_A_CONSOLE"},
                          {intr, "INTERRUPTED"}, {typed("yes\r\n"), "WRONG_CONFIRMATION"}, {typed(""), "WRONG_CONFIRMATION"}};
    for (const auto& c : cases) {
        Fake f;
        f.defender = {def_obs("Normal", kOld)};
        f.approval = c.in;
        const ScanReport r = run_scan({}, f.hooks());
        CHECK(r.status == ScanStatus::RefusedNotApproved);
        CHECK(r.approval_asked && !r.approval.approved && r.approval.reason == c.reason);
        CHECK(f.start_calls == 0 && !r.start_attempted);
        CHECK(r.approved_at_utc.empty());
        CHECK(scan_exit_code(r.status) == 4);
    }
}

void test_run_gate_rechecked_after_approval() {
    // Defender flips to passive while the human is typing: approved, but Start must not run.
    Fake f;
    f.defender = {def_obs("Normal", kOld), def_obs("Passive", kOld)};
    const ScanReport r = run_scan({}, f.hooks());
    CHECK(r.status == ScanStatus::RefusedNotApplicable);
    CHECK(f.ask_calls == 1 && f.start_calls == 0 && !r.start_attempted);
    CHECK(r.gate.code == "MODE_PASSIVE");
    Fake g;
    DefenderScanObservation lost;
    lost.obs = Obs::Unknown;
    lost.error_code = "TIMEOUT";
    g.defender = {def_obs("Normal", kOld), lost};
    CHECK(run_scan({}, g.hooks()).status == ScanStatus::RefusedNotApplicable && g.start_calls == 0);
}

void test_run_failures_are_reported_not_hidden() {
    {
        Fake f;
        f.defender = {def_obs("Normal", kOld)};
        f.start.exec_hr = kWbemAccessDenied;
        const ScanReport r = run_scan({}, f.hooks());
        CHECK(r.status == ScanStatus::AccessDenied && f.start_calls == 1);
        CHECK(scan_exit_code(r.status) == 2);
        CHECK(render_scan_json(r, "1").find("\"exec_result\":\"HRESULT:0x80041003\"") != std::string::npos);
        CHECK(render_scan_text(r, "1").find("denied") != std::string::npos);
    }
    {
        Fake f;
        f.defender = {def_obs("Normal", kOld)};
        f.start.exec_hr = kOtherFail;
        CHECK(run_scan({}, f.hooks()).status == ScanStatus::StartFailed);
    }
    {  // Start "succeeds" but Defender shows nothing new: not confirmed (exit 3).
        Fake f;
        f.defender = {def_obs("Normal", kOld)};
        const ScanReport r = run_scan({}, f.hooks());
        CHECK(r.status == ScanStatus::NotConfirmed && !r.new_scan_confirmed);
        CHECK(scan_exit_code(r.status) == 3);
    }
    {  // Defender cannot be re-read afterwards.
        Fake f;
        DefenderScanObservation lost;
        lost.obs = Obs::Unknown;
        lost.error_code = "TIMEOUT";
        f.defender = {def_obs("Normal", kOld), def_obs("Normal", kOld), lost};
        const ScanReport r = run_scan({}, f.hooks());
        CHECK(r.status == ScanStatus::NotConfirmed && !r.after);
        CHECK(render_scan_text(r, "1").find("could not be re-read") != std::string::npos);
    }
    {  // Ctrl+C while waiting.
        Fake f;
        f.defender = {def_obs("Normal", kOld), def_obs("Normal", kOld), def_obs("Normal", ScanTimes{kT1, kOld.quick_end})};
        f.start.wait = WaitEnd::Interrupted;
        const ScanReport r = run_scan({}, f.hooks());
        CHECK(r.status == ScanStatus::StartedNotCompleted && scan_exit_code(r.status) == 3);
        CHECK(render_scan_json(r, "1").find("\"wait\":\"interrupted\"") != std::string::npos);
    }
}

void test_run_start_called_at_most_once_and_only_when_approved() {
    // Sweep: every combination of mode x approval; Start runs iff mode is Normal AND approval is valid.
    const char* modes[] = {"Normal", "Passive", "Not running", "normal", ""};
    const char* lines[] = {"START QUICK SCAN\r\n", "START QUICK SCAN", "no", "", "start quick scan\r\n"};
    for (const char* m : modes)
        for (const char* l : lines)
            for (int console = 0; console < 2; ++console) {
                Fake f;
                f.defender = {def_obs(m, kOld)};
                f.approval = typed(l);
                f.approval.input_is_console = console == 1;
                run_scan({}, f.hooks());
                const bool should = std::string(m) == "Normal" && console == 1 && std::string(l).rfind("START QUICK SCAN", 0) == 0;
                CHECK((f.start_calls == 1) == should);
                CHECK(f.start_calls <= 1);
            }
}

void test_args() {
    auto parse = [](std::vector<std::string_view> v) { return parse_args(v); };
    auto p = parse({"scan", "--quick"});
    CHECK(p.command == Command::Scan && !p.dry_run && !p.json);
    p = parse({"scan", "--quick", "--dry-run", "--json"});
    CHECK(p.command == Command::Scan && p.dry_run && p.json);
    p = parse({"scan", "--json", "--dry-run", "--quick"});
    CHECK(p.command == Command::Scan && p.dry_run && p.json);
    for (auto bad : std::vector<std::vector<std::string_view>>{
             {"scan"}, {"scan", "--json"}, {"scan", "--dry-run"}, {"scan", "--full"}, {"scan", "--quick", "--quick"},
             {"scan", "--quick", "--dry-run", "--dry-run"}, {"scan", "--quick", "--yes"}, {"scan", "--quick", "--force"},
             {"scan", "--quick", "extra"}, {"scan", "--quick", "C:\\Windows"}, {"scan", "--custom", "C:\\"}}) {
        const ParsedArgs b = parse(bad);
        CHECK(b.command == Command::Invalid && !b.error.empty());
    }
    CHECK(usage_text("1").find("scan --quick") != std::string::npos);
}

void test_render_hostile() {
    Fake f;
    f.defender = {def_obs("Passive\"\n\x1b[31m")};
    f.av = av_with({{"Ev\"il\n\x1b[2JAV", 0x061000}});
    const ScanReport r = run_scan({}, f.hooks());
    const std::string t = render_scan_text(r, "1");
    CHECK(t.find('\x1b') == std::string::npos);
    const std::string j = render_scan_json(r, "1");
    CHECK(j.find('\x1b') == std::string::npos);
    CHECK(j.find("\\n") == std::string::npos || j.find('\n') == j.size() - 1);
}

}  // namespace

int main() {
    test_datetime();
    test_gate();
    test_approval();
    test_outcome();
    test_run_happy_path();
    test_run_dry_run_never_asks_or_starts();
    test_run_gate_refusal_never_asks_or_starts();
    test_run_approval_refusals_never_start();
    test_run_gate_rechecked_after_approval();
    test_run_failures_are_reported_not_hidden();
    test_run_start_called_at_most_once_and_only_when_approved();
    test_args();
    test_render_hostile();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
