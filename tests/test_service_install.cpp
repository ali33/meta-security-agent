// Deterministic tests for `service install` / `service uninstall` (core/service_install). Everything
// the Windows layer would do (elevation, exe path, SCM, console approval, CreateService/DeleteService)
// is a fake here, so the central safety claim is PROVEN, not assumed: the create/delete hook is never
// called without Administrator rights AND a valid typed approval, never on --dry-run, never for a
// binary outside a protected directory. No OS access.
#include <cstdio>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/json.hpp"
#include "core/service_install.hpp"

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

bool contains(const std::string& s, const std::string& what) { return s.find(what) != std::string::npos; }

const std::vector<std::string> kRoots = {"C:\\Program Files", "C:\\Program Files (x86)", "C:\\Windows"};
const char* kGoodExe = "C:\\Program Files\\META\\meta-sec.exe";

ApprovalInput typed(const std::string& line, bool console = true) {
    ApprovalInput in;
    in.input_is_console = console;
    in.output_is_console = console;
    in.read = ReadStatus::Ok;
    in.line = line;
    return in;
}

struct Fake {
    bool elevated = true;
    bool elevated_after_prompt = true;  // what a second look finds (the human took a while)
    std::string exe = kGoodExe;
    std::string exposure;               // "" = fine
    bool query_ok = true;
    bool exists = false;
    bool exists_after_prompt = false;
    ApprovalInput approval = typed("INSTALL SERVICE\r\n");
    ServiceChangeOutcome install_result{true, false, "", "created"};
    ServiceChangeOutcome uninstall_result{true, false, "", "stopped and deleted"};
    bool throw_on_change = false;
    bool no_exposure_hook = false;
    bool no_audit_hook = false;
    bool audit_result = true;
    bool audit_throws = false;
    int audit_calls = 0;
    std::string audit_action, audit_actor, audit_outcome;

    int elevated_calls = 0, query_calls = 0, ask_calls = 0, install_calls = 0, uninstall_calls = 0;
    std::string installed_path;
    std::string last_prompt;

    ServiceChangeHooks hooks() {
        ServiceChangeHooks h;
        h.elevated = [this] { return ++elevated_calls == 1 ? elevated : elevated_after_prompt; };
        h.resolve_exe_path = [this] { return exe; };
        h.trusted_roots = [] { return kRoots; };
        if (!no_exposure_hook)
            h.binary_exposure = [this](const std::string&, const std::vector<std::string>&) { return exposure; };
        if (!no_audit_hook)
            h.record_audit = [this](const std::string& a, const std::string& who, const std::string& res) {
                ++audit_calls;
                audit_action = a;
                audit_actor = who;
                audit_outcome = res;
                if (audit_throws) throw std::runtime_error("event log");
                return audit_result;
            };
        h.query_service = [this] {
            ++query_calls;
            ServiceInfo i;
            i.query_ok = query_ok;
            if (!query_ok) i.query_error = "ACCESS_DENIED";
            const bool e = ask_calls == 0 ? exists : exists_after_prompt;
            i.install = e ? InstallState::Installed : InstallState::NotInstalled;
            return i;
        };
        h.ask_approval = [this](const std::string& prompt) {
            ++ask_calls;
            last_prompt = prompt;
            return approval;
        };
        h.actor = [] { return std::string("HOST\\alice"); };
        h.now_utc = [] { return std::string("2026-10-30T12:00:00Z"); };
        h.install = [this](const std::string& path) {
            ++install_calls;
            installed_path = path;
            if (throw_on_change) throw std::runtime_error("boom");
            return install_result;
        };
        h.uninstall = [this] {
            ++uninstall_calls;
            if (throw_on_change) throw std::runtime_error("boom");
            return uninstall_result;
        };
        return h;
    }
};

ServiceChangeOptions opt(ServiceChange c, bool dry = false) {
    ServiceChangeOptions o;
    o.change = c;
    o.dry_run = dry;
    return o;
}

void test_path_policy() {
    auto ok = [](const char* p) { return evaluate_service_binary_path(p, kRoots).allowed; };
    auto code = [](const char* p) { return evaluate_service_binary_path(p, kRoots).code; };
    CHECK(ok("C:\\Program Files\\META\\meta-sec.exe"));
    CHECK(ok("c:\\program files\\meta\\META-SEC.EXE"));                // case-insensitive
    CHECK(ok("C:\\Program Files (x86)\\META Security\\meta-sec.exe"));  // spaces and parentheses are fine (quoted)
    CHECK(ok("C:\\Windows\\System32\\meta-sec.exe"));
    CHECK(code("C:\\Program Files\\META\\meta-sec.exe") == "PATH_OK");

    // outside every protected root
    CHECK(code("D:\\META\\META-Security-Agent\\build\\Release\\meta-sec.exe") == "PATH_NOT_IN_PROTECTED_LOCATION");
    CHECK(code("C:\\Users\\bob\\Downloads\\meta-sec.exe") == "PATH_NOT_IN_PROTECTED_LOCATION");
    CHECK(code("C:\\ProgramData\\META\\meta-sec.exe") == "PATH_NOT_IN_PROTECTED_LOCATION");
    CHECK(code("C:\\Program Files Evil\\meta-sec.exe") == "PATH_NOT_IN_PROTECTED_LOCATION");  // prefix of the name, not a directory
    CHECK(code("C:\\Program Filesx\\meta-sec.exe") == "PATH_NOT_IN_PROTECTED_LOCATION");
    CHECK(!ok("C:\\Program Files"));       // the root itself is not a file inside it
    CHECK(!ok("C:\\Program Files\\"));
    // shape
    CHECK(code("") == "PATH_UNKNOWN");
    CHECK(code("meta-sec.exe") == "PATH_NOT_ABSOLUTE");
    CHECK(code("\\\\server\\share\\meta-sec.exe") == "PATH_NOT_ABSOLUTE");
    CHECK(code("\\\\?\\C:\\Program Files\\meta-sec.exe") != "PATH_OK");
    CHECK(code("C:\\Program Files\\..\\Users\\bob\\meta-sec.exe") == "PATH_NOT_ABSOLUTE");
    CHECK(code("C:\\Program Files\\.\\meta-sec.exe") == "PATH_NOT_ABSOLUTE");
    CHECK(code("C:\\Program Files\\\\meta-sec.exe") == "PATH_NOT_ABSOLUTE");
    CHECK(code("C:/Program Files/meta-sec.exe") == "PATH_ODD_CHARACTERS");
    CHECK(code("C:\\Program Files\\meta\"sec.exe") == "PATH_ODD_CHARACTERS");
    CHECK(code("C:\\Program Files\\a&b\\meta-sec.exe") == "PATH_ODD_CHARACTERS");
    CHECK(code("C:\\Program Files\\%TEMP%\\meta-sec.exe") == "PATH_ODD_CHARACTERS");
    CHECK(code("C:\\Program Files\\a^b\\meta-sec.exe") == "PATH_ODD_CHARACTERS");
    CHECK(code("C:\\Program Files\\a;b\\meta-sec.exe") == "PATH_ODD_CHARACTERS");
    CHECK(code("C:\\Program Files\\a\nb\\meta-sec.exe") == "PATH_ODD_CHARACTERS");
    CHECK(code("C:\\Program Files\\meta-sec.exe:stream") == "PATH_ODD_CHARACTERS");  // alternate data stream
    CHECK(code("C:\\Program Files\\dir.\\meta-sec.exe") == "PATH_ODD_CHARACTERS");   // trailing dot is normalized away by Windows
    CHECK(code("C:\\Program Files\\meta-sec.txt") == "PATH_NOT_EXE");
    CHECK(code("C:\\Program Files\\meta-sec") == "PATH_NOT_EXE");
    CHECK(code(("C:\\Program Files\\" + std::string(300, 'a') + ".exe").c_str()) == "PATH_ODD_CHARACTERS");  // too long
    // a root list that is empty, or contains only junk or a drive root, trusts nothing
    CHECK(!evaluate_service_binary_path(kGoodExe, {}).allowed);
    CHECK(!evaluate_service_binary_path(kGoodExe, {"", "relative", "C:\\"}).allowed);
    CHECK(!evaluate_service_binary_path("C:\\x\\meta-sec.exe", {"C:\\"}).allowed);
    // a root with a trailing backslash still works
    CHECK(evaluate_service_binary_path(kGoodExe, {"C:\\Program Files\\"}).allowed);
    // refusals explain themselves
    CHECK(contains(evaluate_service_binary_path("C:\\Users\\bob\\meta-sec.exe", kRoots).message, "privilege escalation"));
}

void test_image_path() {
    CHECK(build_service_image_path(kGoodExe) == "\"C:\\Program Files\\META\\meta-sec.exe\" service run --scm");
    CHECK(build_service_image_path("C:\\Program Files\\x\\a b.exe").front() == '"');
    CHECK(build_service_image_path("").empty());
    CHECK(build_service_image_path("C:\\a\"b\\x.exe").empty());   // would break the quoting
    CHECK(build_service_image_path("relative.exe").empty());
    CHECK(build_service_image_path("C:\\a&b\\x.exe").empty());
}

void test_exit_codes_and_names() {
    CHECK(service_change_exit_code(ServiceChangeStatus::Done) == 0);
    CHECK(service_change_exit_code(ServiceChangeStatus::DryRunWouldProceed) == 0);
    CHECK(service_change_exit_code(ServiceChangeStatus::NoOpNotInstalled) == 0);
    CHECK(service_change_exit_code(ServiceChangeStatus::RefusedNotElevated) == 4);
    CHECK(service_change_exit_code(ServiceChangeStatus::RefusedBadBinaryPath) == 4);
    CHECK(service_change_exit_code(ServiceChangeStatus::RefusedAlreadyInstalled) == 4);
    CHECK(service_change_exit_code(ServiceChangeStatus::RefusedNotApproved) == 4);
    CHECK(service_change_exit_code(ServiceChangeStatus::Failed) == 2);
    CHECK(service_change_exit_code(ServiceChangeStatus::Incomplete) == 3);
    CHECK(std::string(to_string(ServiceChangeStatus::RefusedBadBinaryPath)) == "REFUSED_BAD_BINARY_PATH");
}

void test_install_happy_path() {
    Fake f;
    const ServiceChangeReport r = run_service_change(opt(ServiceChange::Install), f.hooks());
    CHECK(r.status == ServiceChangeStatus::Done);
    CHECK(f.install_calls == 1 && f.uninstall_calls == 0);
    CHECK(f.installed_path == kGoodExe);
    CHECK(r.approval_asked && r.approval.approved && r.actor == "HOST\\alice" && r.approved_at_utc == "2026-10-30T12:00:00Z");
    CHECK(contains(f.last_prompt, "INSTALL SERVICE"));
    CHECK(service_change_exit_code(r.status) == 0);
}

void test_install_refusals_ask_nothing() {
    {  // not elevated: nothing prompted, nothing observed, nothing done -- even on dry-run
        for (bool dry : {false, true}) {
            Fake f;
            f.elevated = false;
            const auto r = run_service_change(opt(ServiceChange::Install, dry), f.hooks());
            CHECK(r.status == ServiceChangeStatus::RefusedNotElevated);
            CHECK(f.ask_calls == 0 && f.install_calls == 0 && f.query_calls == 0);
        }
    }
    {  // bad path: refused before the prompt
        Fake f;
        f.exe = "D:\\build\\meta-sec.exe";
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::RefusedBadBinaryPath);
        CHECK(f.ask_calls == 0 && f.install_calls == 0 && f.query_calls == 0);
        CHECK(!r.path.allowed && r.path.code == "PATH_NOT_IN_PROTECTED_LOCATION");
    }
    {  // inside Windows\ but world-writable (Temp): the exposure look refuses
        Fake f;
        f.exe = "C:\\Windows\\Temp\\meta-sec.exe";
        f.exposure = "Users can modify C:\\Windows\\Temp";
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::RefusedBadBinaryPath && r.path.code == "PATH_WRITABLE_BY_NON_ADMINS");
        CHECK(f.ask_calls == 0 && f.install_calls == 0);
    }
    {  // unknown exe path
        Fake f;
        f.exe = "";
        CHECK(run_service_change(opt(ServiceChange::Install), f.hooks()).status == ServiceChangeStatus::RefusedBadBinaryPath);
        CHECK(f.install_calls == 0);
    }
    {  // already installed: a refusal, not an error; nothing prompted
        Fake f;
        f.exists = true;
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::RefusedAlreadyInstalled && service_change_exit_code(r.status) == 4);
        CHECK(contains(render_service_change_text(r, "1"), "already installed"));
        CHECK(f.ask_calls == 0 && f.install_calls == 0);
    }
    {  // SCM cannot be queried: incomplete (3), nothing done
        Fake f;
        f.query_ok = false;
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::Incomplete && service_change_exit_code(r.status) == 3);
        CHECK(f.ask_calls == 0 && f.install_calls == 0);
    }
}

void test_exposure_check_fails_closed() {
    Fake f;
    f.no_exposure_hook = true;  // a Windows layer that forgot the hook must not silently skip the look
    const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
    CHECK(r.status == ServiceChangeStatus::RefusedBadBinaryPath && r.path.code == "PATH_EXPOSURE_UNCHECKED");
    CHECK(f.ask_calls == 0 && f.install_calls == 0);
}

void test_audit_record() {
    {  // recorded: action, actor, result code; visible in the report
        Fake f;
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::Done && r.audit_attempted && r.audit_recorded);
        CHECK(f.audit_calls == 1 && f.audit_action == "install" && f.audit_actor == "HOST\\alice" && f.audit_outcome == "DONE");
        const std::string j = render_service_change_json(r, "1");
        const auto p = json_parse(j.substr(0, j.size() - 1));
        CHECK(p.ok && p.value.find("audit_recorded")->boolean == true && p.value.find("audit_attempted")->boolean == true);
        CHECK(contains(render_service_change_text(r, "1"), "recorded in the Windows Event Log"));
    }
    {  // cannot be recorded: the outcome is NOT faked in either direction, and the gap is visible
        for (int mode = 0; mode < 3; ++mode) {
            Fake f;
            f.audit_result = false;
            f.audit_throws = mode == 1;
            f.no_audit_hook = mode == 2;
            const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
            CHECK(r.status == ServiceChangeStatus::Done && service_change_exit_code(r.status) == 0);
            CHECK(r.audit_attempted && !r.audit_recorded);
            const std::string j = render_service_change_json(r, "1");
            const auto p = json_parse(j.substr(0, j.size() - 1));
            CHECK(p.ok && p.value.find("audit_recorded")->boolean == false);
            CHECK(p.ok && contains(p.value.find("message")->string, "NOT be written"));
            CHECK(contains(render_service_change_text(r, "1"), "NOT recorded"));
        }
    }
    {  // a failed change is recorded too, with its result; a refusal or dry run records nothing
        Fake f;
        f.install_result = {false, false, "WIN32:5", "denied"};
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::Failed && f.audit_calls == 1 && f.audit_outcome == "FAILED" && r.audit_recorded);
        Fake d;
        run_service_change(opt(ServiceChange::Install, true), d.hooks());
        Fake n;
        n.elevated = false;
        run_service_change(opt(ServiceChange::Install), n.hooks());
        Fake a;
        a.approval = typed("no");
        run_service_change(opt(ServiceChange::Install), a.hooks());
        CHECK(d.audit_calls == 0 && n.audit_calls == 0 && a.audit_calls == 0);
        Fake u;
        u.exists = u.exists_after_prompt = true;
        u.approval = typed("UNINSTALL SERVICE\r\n");
        const auto ur = run_service_change(opt(ServiceChange::Uninstall), u.hooks());
        CHECK(ur.status == ServiceChangeStatus::Done && u.audit_calls == 1 && u.audit_action == "uninstall");
    }
}

void test_prompt_shows_what_will_change() {
    Fake f;
    run_service_change(opt(ServiceChange::Install), f.hooks());
    CHECK(contains(f.last_prompt, "\"C:\\Program Files\\META\\meta-sec.exe\" service run --scm"));
    CHECK(contains(f.last_prompt, kServiceAccountName));
    CHECK(contains(f.last_prompt, "INSTALL SERVICE"));
}

void test_display_sanitizing() {
    // ASCII controls, C1 controls (CSI U+009B), bidi overrides/isolates/marks are neutralized; normal UTF-8 is kept
    CHECK(strip_unsafe_display("a\x1b[31mb") == "a?[31mb");
    CHECK(strip_unsafe_display("x\xC2\x9B" "31m") == "x?31m");
    CHECK(strip_unsafe_display("x\xC2\x85y") == "x?y");
    CHECK(strip_unsafe_display("a\xE2\x80\xAE" "b") == "a?b");
    CHECK(strip_unsafe_display("a\xE2\x80\xAA" "b\xE2\x80\xAC") == "a?b?");
    CHECK(strip_unsafe_display("a\xE2\x81\xA6" "b\xE2\x81\xA9") == "a?b?");
    CHECK(strip_unsafe_display("a\xE2\x80\x8E" "b\xD8\x9C") == "a?b?");
    CHECK(strip_unsafe_display("Tu\xC3\xA2n \xE2\x80\x93 ok") == "Tu\xC3\xA2n \xE2\x80\x93 ok");  // U+00E2 and U+2013 untouched
    Fake f;
    f.install_result = {false, false, "E\xC2\x9B", "d\xE2\x80\xAE" "evil\xE2\x81\xA7"};
    const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
    const std::string t = render_service_change_text(r, "1");
    const std::string j = render_service_change_json(r, "1");
    for (const std::string& s : {t, j}) {
        CHECK(s.find("\xC2\x9B") == std::string::npos);
        CHECK(s.find("\xE2\x80\xAE") == std::string::npos);
        CHECK(s.find("\xE2\x81\xA7") == std::string::npos);
    }
}

void test_dry_run() {
    Fake f;
    const auto r = run_service_change(opt(ServiceChange::Install, true), f.hooks());
    CHECK(r.status == ServiceChangeStatus::DryRunWouldProceed && service_change_exit_code(r.status) == 0);
    CHECK(f.ask_calls == 0 && f.install_calls == 0 && f.uninstall_calls == 0);
    CHECK(!r.approval_asked && !r.change_attempted);
    Fake g;
    g.exists = true;
    const auto u = run_service_change(opt(ServiceChange::Uninstall, true), g.hooks());
    CHECK(u.status == ServiceChangeStatus::DryRunWouldProceed);
    CHECK(g.ask_calls == 0 && g.uninstall_calls == 0);
    // uninstall dry-run when absent is the no-op
    Fake n;
    CHECK(run_service_change(opt(ServiceChange::Uninstall, true), n.hooks()).status == ServiceChangeStatus::NoOpNotInstalled);
}

void test_approval_refusals() {
    const std::vector<ApprovalInput> bad = {
        typed("INSTALL SERVICE\r\n", false),  // not a console
        typed("install service\r\n"),         // wrong case
        typed("INSTALL SERVICE"),             // no Enter
        typed("START QUICK SCAN\r\n"),        // another action's phrase
        typed("UNINSTALL SERVICE\r\n"),       // the other direction's phrase
        typed("INSTALL SERVICE please\r\n"),
        typed("\r\n"),
    };
    for (const auto& a : bad) {
        Fake f;
        f.approval = a;
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::RefusedNotApproved && service_change_exit_code(r.status) == 4);
        CHECK(f.ask_calls == 1 && f.install_calls == 0);
    }
    for (ReadStatus rs : {ReadStatus::Eof, ReadStatus::Error, ReadStatus::Interrupted}) {
        Fake f;
        f.approval = typed("INSTALL SERVICE\r\n");
        f.approval.read = rs;
        CHECK(run_service_change(opt(ServiceChange::Install), f.hooks()).status == ServiceChangeStatus::RefusedNotApproved);
        CHECK(f.install_calls == 0);
    }
    {  // uninstall needs ITS phrase, not the install one
        Fake f;
        f.exists = f.exists_after_prompt = true;
        f.approval = typed("INSTALL SERVICE\r\n");
        CHECK(run_service_change(opt(ServiceChange::Uninstall), f.hooks()).status == ServiceChangeStatus::RefusedNotApproved);
        CHECK(f.uninstall_calls == 0);
        f.approval = typed("UNINSTALL SERVICE\r\n");
        CHECK(run_service_change(opt(ServiceChange::Uninstall), f.hooks()).status == ServiceChangeStatus::Done);
        CHECK(f.uninstall_calls == 1);
    }
}

void test_recheck_after_prompt() {
    {  // elevation lost while the prompt was open
        Fake f;
        f.elevated_after_prompt = false;
        CHECK(run_service_change(opt(ServiceChange::Install), f.hooks()).status == ServiceChangeStatus::RefusedNotElevated);
        CHECK(f.install_calls == 0);
    }
    {  // somebody created the service meanwhile
        Fake f;
        f.exists_after_prompt = true;
        CHECK(run_service_change(opt(ServiceChange::Install), f.hooks()).status == ServiceChangeStatus::RefusedAlreadyInstalled);
        CHECK(f.install_calls == 0);
    }
    {  // somebody removed it meanwhile: uninstall becomes the no-op
        Fake f;
        f.exists = true;
        f.exists_after_prompt = false;
        f.approval = typed("UNINSTALL SERVICE\r\n");
        CHECK(run_service_change(opt(ServiceChange::Uninstall), f.hooks()).status == ServiceChangeStatus::NoOpNotInstalled);
        CHECK(f.uninstall_calls == 0);
    }
}

void test_uninstall_noop_and_outcomes() {
    {  // not installed: valid no-op, exit 0, nothing prompted or called
        Fake f;
        const auto r = run_service_change(opt(ServiceChange::Uninstall), f.hooks());
        CHECK(r.status == ServiceChangeStatus::NoOpNotInstalled && service_change_exit_code(r.status) == 0);
        CHECK(f.ask_calls == 0 && f.uninstall_calls == 0);
    }
    {  // not elevated beats everything, also for uninstall
        Fake f;
        f.elevated = false;
        f.exists = true;
        CHECK(run_service_change(opt(ServiceChange::Uninstall), f.hooks()).status == ServiceChangeStatus::RefusedNotElevated);
        CHECK(f.uninstall_calls == 0 && f.ask_calls == 0);
    }
    {  // failure / incomplete / exception
        Fake f;
        f.exists = f.exists_after_prompt = true;
        f.approval = typed("UNINSTALL SERVICE\r\n");
        f.uninstall_result = {false, false, "WIN32:5", "DeleteService failed"};
        auto r = run_service_change(opt(ServiceChange::Uninstall), f.hooks());
        CHECK(r.status == ServiceChangeStatus::Failed && service_change_exit_code(r.status) == 2);
        f.uninstall_result = {false, true, "STOP_TIMEOUT", "did not stop"};
        r = run_service_change(opt(ServiceChange::Uninstall), f.hooks());
        CHECK(r.status == ServiceChangeStatus::Incomplete && service_change_exit_code(r.status) == 3);
        f.throw_on_change = true;
        r = run_service_change(opt(ServiceChange::Uninstall), f.hooks());
        CHECK(r.status == ServiceChangeStatus::Failed && r.outcome.error_code == "EXCEPTION");
    }
    {
        Fake f;
        f.install_result = {false, false, "WIN32:5", "CreateService failed"};
        const auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
        CHECK(r.status == ServiceChangeStatus::Failed && f.install_calls == 1);
    }
}

// THE sweep: every combination of the gates. The side-effect hook runs exactly when ALL of them pass.
void test_gate_sweep_install() {
    const char* exes[] = {kGoodExe, "D:\\build\\meta-sec.exe", "C:\\Users\\bob\\meta-sec.exe", "\\\\srv\\share\\meta-sec.exe",
                          "C:\\Program Files\\a\"b\\meta-sec.exe", ""};
    const char* exposures[] = {"", "Users can modify X"};
    const char* lines[] = {"INSTALL SERVICE\r\n", "INSTALL SERVICE\n", "no", "", "install service\r\n", "UNINSTALL SERVICE\r\n"};
    int combos = 0, runs = 0;
    for (int elevated = 0; elevated < 2; ++elevated)
        for (const char* exe : exes)
            for (const char* exposure : exposures)
                for (int exists = 0; exists < 2; ++exists)
                    for (int query_ok = 0; query_ok < 2; ++query_ok)
                        for (const char* line : lines)
                            for (int console = 0; console < 2; ++console)
                                for (int dry = 0; dry < 2; ++dry) {
                                    Fake f;
                                    f.elevated = f.elevated_after_prompt = elevated == 1;
                                    f.exe = exe;
                                    f.exposure = exposure;
                                    f.exists = f.exists_after_prompt = exists == 1;
                                    f.query_ok = query_ok == 1;
                                    f.approval = typed(line, console == 1);
                                    run_service_change(opt(ServiceChange::Install, dry == 1), f.hooks());
                                    const bool path_ok = evaluate_service_binary_path(exe, kRoots).allowed && std::string(exposure).empty();
                                    const bool approved = console == 1 && std::string(line).rfind("INSTALL SERVICE", 0) == 0;
                                    const bool should = elevated == 1 && path_ok && query_ok == 1 && exists == 0 && dry == 0 && approved;
                                    ++combos;
                                    if (should) ++runs;
                                    CHECK((f.install_calls == 1) == should);
                                    CHECK(f.install_calls <= 1);
                                    CHECK(f.uninstall_calls == 0);
                                    // no prompt unless every earlier gate passed
                                    if (!(elevated == 1 && path_ok && query_ok == 1 && exists == 0 && dry == 0)) CHECK(f.ask_calls == 0);
                                }
    CHECK(combos == 2 * 6 * 2 * 2 * 2 * 6 * 2 * 2);
    CHECK(runs > 0);  // the sweep does reach the side effect in the one all-green corner
}

void test_gate_sweep_uninstall() {
    const char* lines[] = {"UNINSTALL SERVICE\r\n", "UNINSTALL SERVICE\n", "no", "", "uninstall service\r\n", "INSTALL SERVICE\r\n"};
    for (int elevated = 0; elevated < 2; ++elevated)
        for (int exists = 0; exists < 2; ++exists)
            for (int query_ok = 0; query_ok < 2; ++query_ok)
                for (const char* line : lines)
                    for (int console = 0; console < 2; ++console)
                        for (int dry = 0; dry < 2; ++dry) {
                            Fake f;
                            f.elevated = f.elevated_after_prompt = elevated == 1;
                            f.exists = f.exists_after_prompt = exists == 1;
                            f.query_ok = query_ok == 1;
                            f.approval = typed(line, console == 1);
                            run_service_change(opt(ServiceChange::Uninstall, dry == 1), f.hooks());
                            const bool approved = console == 1 && std::string(line).rfind("UNINSTALL SERVICE", 0) == 0;
                            const bool should = elevated == 1 && query_ok == 1 && exists == 1 && dry == 0 && approved;
                            CHECK((f.uninstall_calls == 1) == should);
                            CHECK(f.uninstall_calls <= 1);
                            CHECK(f.install_calls == 0);
                            if (!(elevated == 1 && query_ok == 1 && exists == 1 && dry == 0)) CHECK(f.ask_calls == 0);
                        }
}

void test_render() {
    Fake f;
    f.exe = "C:\\Users\\bob\\Downloads\\meta-sec.exe";
    f.elevated = true;
    auto r = run_service_change(opt(ServiceChange::Install), f.hooks());
    std::string j = render_service_change_json(r, "9.9.9");
    auto p = json_parse(j.substr(0, j.size() - 1));
    CHECK(p.ok && j.back() == '\n' && j.find('\n') == j.size() - 1);
    CHECK(p.ok && p.value.find("schema_version")->integer == 1);
    CHECK(p.ok && p.value.find("command")->string == "service install");
    CHECK(p.ok && p.value.find("status")->string == "REFUSED_BAD_BINARY_PATH");
    CHECK(p.ok && p.value.find("exit_code")->integer == 4);
    CHECK(p.ok && p.value.find("binary")->find("allowed")->boolean == false);
    CHECK(p.ok && p.value.find("binary")->find("path")->string.find("<user>") != std::string::npos);  // profile redacted
    CHECK(p.ok && p.value.find("change")->find("attempted")->boolean == false);
    CHECK(p.ok && p.value.find("approval")->find("asked")->boolean == false);

    Fake u;
    u.exists = u.exists_after_prompt = true;
    u.approval = typed("UNINSTALL SERVICE\r\n");
    r = run_service_change(opt(ServiceChange::Uninstall), u.hooks());
    j = render_service_change_json(r, "9.9.9");
    p = json_parse(j.substr(0, j.size() - 1));
    CHECK(p.ok && p.value.find("command")->string == "service uninstall" && p.value.find("status")->string == "DONE");
    CHECK(p.ok && p.value.find("binary") == nullptr);
    CHECK(p.ok && p.value.find("change")->find("ok")->boolean == true);
    CHECK(contains(render_service_change_text(r, "9.9.9"), "data directory"));

    // hostile strings from the Windows layer never break the JSON or reach the terminal raw
    Fake h;
    h.exists = h.exists_after_prompt = false;
    h.install_result = {false, false, "WIN32:\"5\"", "bad\x1b[31m\n\"quote\""};
    r = run_service_change(opt(ServiceChange::Install), h.hooks());
    j = render_service_change_json(r, "1");
    p = json_parse(j.substr(0, j.size() - 1));
    CHECK(p.ok && j.find('\x1b') == std::string::npos);
    const std::string t = render_service_change_text(r, "1");
    CHECK(t.find('\x1b') == std::string::npos);
}

}  // namespace

int main() {
    test_path_policy();
    test_image_path();
    test_exit_codes_and_names();
    test_install_happy_path();
    test_install_refusals_ask_nothing();
    test_exposure_check_fails_closed();
    test_audit_record();
    test_prompt_shows_what_will_change();
    test_display_sanitizing();
    test_dry_run();
    test_approval_refusals();
    test_recheck_after_prompt();
    test_uninstall_noop_and_outcomes();
    test_gate_sweep_install();
    test_gate_sweep_uninstall();
    test_render();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
