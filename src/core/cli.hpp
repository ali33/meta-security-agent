#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace metasec {

enum class Command { Help, Version, Status, Audit, Watch, Scan, Service, Invalid };

// `service <sub>` (MVP-4). `Run` is the foreground observer (--console) or the SCM entry (--scm).
enum class ServiceCommand { None, Status, Events, Install, Uninstall, Run };

// Limits shared with the Windows half (validated here, in the pure parser).
constexpr int kMinEventsLimit = 1;
constexpr int kMaxEventsLimit = 200;
constexpr int kDefaultEventsLimit = 50;

struct ParsedArgs {
    Command command = Command::Invalid;
    bool json = false;
    // watch only (defaults from core/watch.hpp)
    int interval_seconds = 30;
    int max_polls = 0;  // 0 = until interrupted
    int confirm_polls = 2;
    // scan, service install/uninstall
    bool dry_run = false;
    // service only
    ServiceCommand service = ServiceCommand::None;
    int limit = kDefaultEventsLimit;  // service events --limit
    bool console = false;             // service run --console (foreground observer, dev/tests)
    bool scm = false;                 // service run --scm (started by the Service Control Manager; internal)
    std::string data_dir;             // service run --console --data-dir (empty = default location)
    std::string pipe_name;            // --pipe-name (empty = default); status/events/run --console
    std::string error;  // set when command == Invalid
};

// `args` excludes argv[0].
ParsedArgs parse_args(const std::vector<std::string_view>& args);

std::string usage_text(const std::string& version);

// Makes an untrusted argument safe to echo on a terminal (control chars -> '?', truncated).
std::string sanitize_for_display(std::string_view s);

}  // namespace metasec
