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
