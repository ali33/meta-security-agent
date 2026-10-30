#include <windows.h>

#include <chrono>
#include <cstdio>
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

}  // namespace

int wmain(int argc, wchar_t** argv) {
    using namespace metasec;
    SetConsoleOutputCP(CP_UTF8);
    const std::string version = META_SEC_VERSION;

    std::vector<std::string> storage;
    for (int i = 1; i < argc; ++i) storage.push_back(wide_to_utf8(argv[i]));
    std::vector<std::string_view> args(storage.begin(), storage.end());

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
            break;
    }

    // One COM apartment on this thread; every provider runs here and releases its
    // interfaces before the apartment is torn down (end of this scope).
    win::ComApartment com;
    if (!com.ok()) {
        std::cerr << "meta-sec: COM initialisation failed: "
                  << hresult_code(static_cast<std::uint32_t>(com.result())) << "\n";
        return kExitError;
    }
    const StatusReport report = win::collect_status(std::chrono::system_clock::now());
    const std::string out =
        parsed.json ? render_status_json(report, version) : render_status_text(report, version);
    if (!write_stdout(out)) {
        std::cerr << "meta-sec: failed to write output\n";
        return kExitError;
    }
    return exit_code_for(compute_overall(report.checks));
}
