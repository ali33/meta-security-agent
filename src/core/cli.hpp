#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace metasec {

enum class Command { Help, Version, Status, Audit, Watch, Invalid };

struct ParsedArgs {
    Command command = Command::Invalid;
    bool json = false;
    // watch only (defaults from core/watch.hpp)
    int interval_seconds = 30;
    int max_polls = 0;  // 0 = until interrupted
    int confirm_polls = 2;
    std::string error;  // set when command == Invalid
};

// `args` excludes argv[0].
ParsedArgs parse_args(const std::vector<std::string_view>& args);

std::string usage_text(const std::string& version);

// Makes an untrusted argument safe to echo on a terminal (control chars -> '?', truncated).
std::string sanitize_for_display(std::string_view s);

}  // namespace metasec
