#include "cli.hpp"

#include "render.hpp"
#include "watch.hpp"

namespace metasec {

namespace {

// Strict decimal integer in [lo, hi]: digits only, no sign, no spaces, at most 9 digits.
bool parse_int_in(std::string_view s, int lo, int hi, int& out) {
    if (s.empty() || s.size() > 9) return false;
    long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    if (v < lo || v > hi) return false;
    out = static_cast<int>(v);
    return true;
}

ParsedArgs parse_watch(const std::vector<std::string_view>& args) {
    ParsedArgs p;
    p.interval_seconds = kDefaultIntervalSeconds;
    p.confirm_polls = kDefaultConfirmPolls;
    bool seen_interval = false, seen_max = false, seen_confirm = false;
    auto value_flag = [&](std::size_t& i, bool& seen, int lo, int hi, int& dst) {
        const std::string name = sanitize_for_display(args[i]);
        if (seen) {
            p.error = "duplicate argument: " + name;
            return false;
        }
        if (i + 1 >= args.size()) {
            p.error = name + " needs a value";
            return false;
        }
        if (!parse_int_in(args[i + 1], lo, hi, dst)) {
            p.error = name + " must be an integer from " + std::to_string(lo) + " to " + std::to_string(hi) +
                      ", got: " + sanitize_for_display(args[i + 1]);
            return false;
        }
        seen = true;
        ++i;
        return true;
    };
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--json" && !p.json) {
            p.json = true;
        } else if (args[i] == "--interval") {
            if (!value_flag(i, seen_interval, kMinIntervalSeconds, kMaxIntervalSeconds, p.interval_seconds)) return p;
        } else if (args[i] == "--max-polls") {
            if (!value_flag(i, seen_max, 1, kMaxPollsLimit, p.max_polls)) return p;
        } else if (args[i] == "--confirm") {
            if (!value_flag(i, seen_confirm, kMinConfirmPolls, kMaxConfirmPolls, p.confirm_polls)) return p;
        } else {
            p.error = "unexpected argument: " + sanitize_for_display(args[i]);
            return p;
        }
    }
    p.command = Command::Watch;
    return p;
}

// scan --quick [--dry-run] [--json]: --quick is mandatory (the only scan type), flags may not repeat.
ParsedArgs parse_scan(const std::vector<std::string_view>& args) {
    ParsedArgs p;
    bool quick = false;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--quick" && !quick) {
            quick = true;
        } else if (args[i] == "--dry-run" && !p.dry_run) {
            p.dry_run = true;
        } else if (args[i] == "--json" && !p.json) {
            p.json = true;
        } else {
            p.error = "unexpected argument: " + sanitize_for_display(args[i]);
            return p;
        }
    }
    if (!quick) {
        p.error = "scan needs --quick (the only scan type supported)";
        return p;
    }
    p.command = Command::Scan;
    return p;
}

}  // namespace

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
    if (cmd == "watch") return parse_watch(args);
    if (cmd == "scan") return parse_scan(args);
    p.error = "unknown command: " + sanitize_for_display(cmd);
    return p;
}

std::string usage_text(const std::string& version) {
    return std::string(kProduct) + " v" + version + " (Standalone; read-only except an approved scan)\n" +
           "Usage:\n"
           "  meta-sec status [--json]   Observe firewall and antivirus state\n"
           "  meta-sec audit [--json]    Check settings against rules (PASS/FAIL/UNKNOWN)\n"
           "  meta-sec watch [--json] [--interval S] [--max-polls N] [--confirm N]\n"
           "                             Report status changes until Ctrl+C (--json: one JSON per line)\n"
           "  meta-sec scan --quick [--dry-run] [--json]\n"
           "                             Start ONE Defender quick scan after typed local approval (--dry-run: check only)\n"
           "  meta-sec --version\n"
           "  meta-sec --help\n"
           "Exit codes: 0 ok, 1 audit violation, 2 command/engine error, "
           "3 incomplete observation (watch: judged on the last poll; scan: not confirmed), "
           "4 scan refused (not applicable or not approved)\n";
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
