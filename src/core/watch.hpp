#pragma once
// MVP-2: change detection between status snapshots. Pure: no Windows headers, no clock, no I/O.
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "types.hpp"

namespace metasec {

// Limits for `watch` options (documented in docs/CLI.md).
constexpr int kDefaultIntervalSeconds = 30;
constexpr int kMinIntervalSeconds = 1;
constexpr int kMaxIntervalSeconds = 3600;
constexpr int kDefaultConfirmPolls = 2;
constexpr int kMinConfirmPolls = 1;
constexpr int kMaxConfirmPolls = 10;
constexpr int kMaxPollsLimit = 1000000;

enum class WatchEventKind {
    Change,               // observed state -> another observed state
    ObservationLost,      // observed state -> UNKNOWN / NOT_SUPPORTED (not "turned off")
    ObservationRestored,  // UNKNOWN / NOT_SUPPORTED -> observed state
    CheckAdded,           // check id appeared
    CheckRemoved,         // check id disappeared
};
const char* to_string(WatchEventKind k);

// One confirmed transition of one check. `from`/`to` are empty for an added/removed check.
struct WatchEvent {
    WatchEventKind kind = WatchEventKind::Change;
    std::string observed_at_utc;        // poll that confirmed the new value
    std::string first_observed_at_utc;  // first poll that showed the new value
    std::string check_id;
    std::optional<State> from;
    std::optional<State> to;
    int confirmations = 0;  // consecutive polls that showed `to` (>= confirm_polls)
    std::string source;
    std::string error_code;
    std::vector<std::pair<std::string, std::string>> evidence;  // of the new value (old one if removed)
};

// Debounced diff. A new value becomes an event only after it was seen on `confirm_polls`
// consecutive polls; a value that reverts before that is dropped silently (flapping and
// transient errors never produce an event). Each confirmed transition yields exactly one event;
// an unchanged value yields none, so nothing is ever replayed.
class WatchTracker {
public:
    explicit WatchTracker(int confirm_polls);
    // The first snapshot: becomes the confirmed state, produces no events.
    void set_baseline(const StatusReport& r);
    bool has_baseline() const { return baseline_; }
    // Feed the next snapshot; returns the events it confirmed, in report order (removed last).
    std::vector<WatchEvent> observe(const StatusReport& r);
    // Currently confirmed state of every check that has one, in tracking order (the persisted
    // checkpoint of the service). Checks that are absent are not listed.
    std::vector<std::pair<std::string, State>> confirmed_states() const;

private:
    struct Entry {
        std::string id;
        std::optional<State> confirmed;
        CheckResult last;  // latest check behind `confirmed` (evidence for a removal)
        bool has_candidate = false;
        std::optional<State> candidate;
        int count = 0;
        std::string first_utc;
    };
    int confirm_;
    bool baseline_ = false;
    std::vector<Entry> entries_;
};

// --- loop -------------------------------------------------------------------------------------

struct WatchOptions {
    bool json = false;
    int interval_seconds = kDefaultIntervalSeconds;
    int max_polls = 0;  // 0 = until interrupted
    int confirm_polls = kDefaultConfirmPolls;
};

// Everything that touches the outside world is injected, so tests drive the loop with fakes.
struct WatchHooks {
    std::function<StatusReport()> snapshot;        // one poll
    std::function<bool(const std::string&)> emit;  // one rendered line; false = output failed
    std::function<bool(int seconds)> wait;         // false = stop requested during the wait
    std::function<bool()> stop_requested;          // polled before every snapshot
    std::function<std::string()> now_utc;          // timestamp for the closing line
};

enum class WatchStop { MaxPolls, Interrupted, OutputFailed, Error };
const char* to_string(WatchStop s);

struct WatchResult {
    WatchStop stop = WatchStop::MaxPolls;
    int polls = 0;
    int events = 0;                       // change events only (not baseline / stopped)
    std::optional<Overall> last_overall;  // of the last raw snapshot; empty if no poll happened
    std::string error;                    // what() of the exception when stop == Error
};

WatchResult run_watch(const WatchOptions& opt, const WatchHooks& hooks, const std::string& version);

// --- rendering --------------------------------------------------------------------------------
// NDJSON: one line each, deterministic key order, "command":"watch", schema_version 1.
std::string render_watch_baseline_json(const StatusReport& r, const WatchOptions& opt, const std::string& version);
std::string render_watch_event_json(const WatchEvent& e);
std::string render_watch_stopped_json(const std::string& at_utc, const WatchResult& res);
// Human-readable lines.
std::string render_watch_baseline_text(const StatusReport& r, const WatchOptions& opt, const std::string& version);
std::string render_watch_event_text(const WatchEvent& e);
std::string render_watch_stopped_text(const std::string& at_utc, const WatchResult& res);

}  // namespace metasec
