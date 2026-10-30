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
    if (cmd == "status" || cmd == "audit") {
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--json" && !p.json) {
                p.json = true;
            } else {
                p.error = "unexpected argument: " + sanitize_for_display(args[i]);
                return p;
            }
        }
        p.command = cmd == "audit" ? Command::Audit : Command::Status;
        return p;
    }
    p.error = "unknown command: " + sanitize_for_display(cmd);
    return p;
}

std::string usage_text(const std::string& version) {
    return std::string(kProduct) + " v" + version + " (Standalone, read-only)\n" +
           "Usage:\n"
           "  meta-sec status [--json]   Observe firewall and antivirus state\n"
           "  meta-sec audit [--json]    Check settings against rules (PASS/FAIL/UNKNOWN)\n"
           "  meta-sec --version\n"
           "  meta-sec --help\n"
           "Exit codes: 0 ok, 1 audit violation, 2 command/engine error, "
           "3 incomplete observation\n";
}

std::string sanitize_for_display(std::string_view s) {
    constexpr std::size_t kMax = 64;
    std::string out;
    std::size_t i = 0;
    for (; i < s.size() && out.size() < kMax; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x20 || c == 0x7F) {
            out += '?';
        } else if (c == 0xC2 && i + 1 < s.size() && static_cast<unsigned char>(s[i + 1]) >= 0x80 &&
                   static_cast<unsigned char>(s[i + 1]) <= 0x9F) {
            out += '?';  // C1 control character (U+0080..U+009F)
            ++i;
        } else if (c >= 0x80) {
            // Copy a whole UTF-8 sequence or nothing, so truncation never splits a character.
            const std::size_t n = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
            if (n == 1) {
                out += '?';  // stray continuation byte
            } else if (i + n <= s.size() && out.size() + n <= kMax) {
                out.append(s.substr(i, n));
                i += n - 1;
            } else {
                break;
            }
        } else {
            out += static_cast<char>(c);
        }
    }
    if (i < s.size()) out += "...";
    return out;
}

}  // namespace metasec
