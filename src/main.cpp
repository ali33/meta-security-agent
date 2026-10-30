#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <chrono>
#include <cstdio>
#include <exception>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "core/cli.hpp"
#include "core/render.hpp"
#include "core/watch.hpp"
#include "win/collect.hpp"

#ifndef META_SEC_VERSION
#define META_SEC_VERSION "0.0.0"
#endif

namespace {

// Writes all of `s` to stdout; false on failure (closed pipe, full disk...).
bool write_stdout(const std::string& s) {
    return std::fwrite(s.data(), 1, s.size(), stdout) == s.size() && std::fflush(stdout) == 0;
}

std::string wide_to_utf8(const wchar_t* w) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<std::size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Sets the console output code page to UTF-8 and restores the previous one on exit.
class Utf8Console {
public:
    Utf8Console() : previous_(GetConsoleOutputCP()) {
        if (previous_ != 0) SetConsoleOutputCP(CP_UTF8);
    }
    ~Utf8Console() {
        if (previous_ != 0) SetConsoleOutputCP(previous_);
    }
    Utf8Console(const Utf8Console&) = delete;
    Utf8Console& operator=(const Utf8Console&) = delete;

private:
    UINT previous_;
};

// Shared by status and audit: validates the caller's COM apartment (which outlives every
// provider); false after a diagnostic on failure.
bool init_com(metasec::win::ComApartment& com) {
    using namespace metasec;
    if (!com.ok()) {
        std::cerr << "meta-sec: COM initialisation failed: "
                  << hresult_code(static_cast<std::uint32_t>(com.result())) << "\n";
        return false;
    }
    if (com.security_result() < 0) {
        // Not fatal: providers report their own failures per check.
        std::cerr << "meta-sec: warning: CoInitializeSecurity failed: "
                  << hresult_code(static_cast<std::uint32_t>(com.security_result())) << "\n";
    }
    return true;
}

int run_status(bool json, const std::string& version) {
    using namespace metasec;
    // One COM apartment on this thread; every provider runs here and releases its
    // interfaces before the apartment is torn down (end of this scope).
    win::ComApartment com;
    if (!init_com(com)) return kExitError;
    const StatusReport report = win::collect_status(std::chrono::system_clock::now());
    const std::string out = json ? render_status_json(report, version) : render_status_text(report, version);
    if (!write_stdout(out)) {
        std::cerr << "meta-sec: failed to write output\n";
        return kExitError;
    }
    return exit_code_for(compute_overall(report.checks));
}

int run_audit_command(bool json, const std::string& version) {
    using namespace metasec;
    win::ComApartment com;
    if (!init_com(com)) return kExitError;
    const AuditReport report = run_audit(win::collect_audit_input(std::chrono::system_clock::now()));
    const std::string out = json ? render_audit_json(report, version) : render_audit_text(report, version);
    if (!write_stdout(out)) {
        std::cerr << "meta-sec: failed to write output\n";
        return kExitError;
    }
    return audit_exit_code(audit_overall(report));
}

// Ctrl+C / Ctrl+Break / console close only signal g_stop_event; the loop stops at its next check.
// g_done_event is signalled once the loop has written its closing line: on console close Windows
// ends the process as soon as the handler returns, so the handler waits for it (bounded).
HANDLE g_stop_event = nullptr;
HANDLE g_done_event = nullptr;

BOOL WINAPI on_console_signal(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            if (g_stop_event) SetEvent(g_stop_event);
            return TRUE;
        case CTRL_CLOSE_EVENT:
            if (g_stop_event) SetEvent(g_stop_event);
            if (g_done_event) WaitForSingleObject(g_done_event, 3000);
            return TRUE;
        default:
            return FALSE;
    }
}

// Owns the two events and the handler registration for the duration of a watch run.
class WatchSignals {
public:
    WatchSignals() {
        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);  // manual reset, unsignalled
        g_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ok_ = g_stop_event && g_done_event && SetConsoleCtrlHandler(on_console_signal, TRUE);
    }
    ~WatchSignals() {
        if (g_done_event) SetEvent(g_done_event);
        SetConsoleCtrlHandler(on_console_signal, FALSE);
        HANDLE stop = g_stop_event, done = g_done_event;
        g_stop_event = g_done_event = nullptr;
        if (stop) CloseHandle(stop);
        if (done) CloseHandle(done);
    }
    WatchSignals(const WatchSignals&) = delete;
    WatchSignals& operator=(const WatchSignals&) = delete;
    bool ok() const { return ok_; }

private:
    bool ok_ = false;
};

int run_watch_command(const metasec::ParsedArgs& parsed, const std::string& version) {
    using namespace metasec;
    win::ComApartment com;
    if (!init_com(com)) return kExitError;
    WatchSignals signals;
    if (!signals.ok()) {
        std::cerr << "meta-sec: cannot install the stop handler\n";
        return kExitError;
    }

    WatchOptions opt;
    opt.json = parsed.json;
    opt.interval_seconds = parsed.interval_seconds;
    opt.max_polls = parsed.max_polls;
    opt.confirm_polls = parsed.confirm_polls;

    WatchHooks hooks;
    hooks.snapshot = [] { return win::collect_status(std::chrono::system_clock::now()); };
    hooks.emit = [](const std::string& line) { return write_stdout(line); };
    hooks.wait = [](int seconds) {
        // Wakes immediately on Ctrl+C; otherwise sleeps without using CPU.
        return WaitForSingleObject(g_stop_event, static_cast<DWORD>(seconds) * 1000) == WAIT_TIMEOUT;
    };
    hooks.stop_requested = [] { return WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0; };
    hooks.now_utc = [] { return format_utc(std::chrono::system_clock::now()); };

    const WatchResult res = run_watch(opt, hooks, version);

    if (res.stop == WatchStop::Error) {
        std::cerr << "meta-sec: watch failed: " << res.error << "\n";
        return kExitError;
    }
    if (res.stop == WatchStop::OutputFailed) {
        std::cerr << "meta-sec: failed to write output\n";
        return kExitError;
    }
    // Same rule as `status`: 3 when the last poll could not observe everything. Never 1.
    return res.last_overall ? exit_code_for(*res.last_overall) : kExitOk;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    using namespace metasec;
    const std::string version = META_SEC_VERSION;
    try {
        Utf8Console console;
        // Binary mode: "\n" is written as-is so JSON bytes are identical on console and pipe.
        _setmode(_fileno(stdout), _O_BINARY);

        std::vector<std::string> storage;
        for (int i = 1; i < argc; ++i) storage.push_back(wide_to_utf8(argv[i]));
        const std::vector<std::string_view> args(storage.begin(), storage.end());

        const ParsedArgs parsed = parse_args(args);
        switch (parsed.command) {
            case Command::Invalid:
                std::cerr << "meta-sec: " << parsed.error << "\n" << usage_text(version);
                return kExitError;
            case Command::Help:
                return write_stdout(usage_text(version)) ? kExitOk : kExitError;
            case Command::Version:
                return write_stdout(version + "\n") ? kExitOk : kExitError;
            case Command::Status:
                return run_status(parsed.json, version);
            case Command::Audit:
                return run_audit_command(parsed.json, version);
            case Command::Watch:
                return run_watch_command(parsed, version);
        }
        return kExitError;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "meta-sec: internal error: %s\n", e.what());
        return kExitError;
    } catch (...) {
        std::fprintf(stderr, "meta-sec: internal error\n");
        return kExitError;
    }
}
