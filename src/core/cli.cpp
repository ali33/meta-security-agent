#include "cli.hpp"

#include "render.hpp"

namespace metasec {

ParsedArgs parse_args(const std::vector<std::string_view>& args) {
    ParsedArgs p;
    if (args.empty()) {
        p.error = "missing command";
        return p;
    }
    const std::string_view cmd = args[0];
    if (cmd == "--help" || cmd == "-h") {
        if (args.size() != 1) {
            p.error = "unexpected argument after " + sanitize_for_display(cmd);
            return p;
        }
        p.command = Command::Help;
        return p;
    }
    if (cmd == "--version") {
        if (args.size() != 1) {
            p.error = "unexpected argument after --version";
            return p;
        }
        p.command = Command::Version;
        return p;
    }
    if (cmd == "status") {
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--json" && !p.json) {
                p.json = true;
            } else {
                p.error = "unexpected argument: " + sanitize_for_display(args[i]);
                return p;
            }
        }
        p.command = Command::Status;
        return p;
    }
    p.error = "unknown command: " + sanitize_for_display(cmd);
    return p;
}

std::string usage_text(const std::string& version) {
    return std::string(kProduct) + " v" + version + " (Standalone, read-only)\n" +
           "Usage:\n"
           "  meta-sec status [--json]   Observe firewall and antivirus state\n"
           "  meta-sec --version\n"
           "  meta-sec --help\n"
           "Exit codes: 0 ok, 1 violation (audit, future), 2 command/engine error, "
           "3 incomplete observation\n";
}

std::string sanitize_for_display(std::string_view s) {
    constexpr std::size_t kMax = 64;
    std::string out;
    for (std::size_t i = 0; i < s.size() && i < kMax; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        out += (c < 0x20 || c == 0x7F) ? '?' : static_cast<char>(c);
    }
    if (s.size() > kMax) out += "...";
    return out;
}

}  // namespace metasec
