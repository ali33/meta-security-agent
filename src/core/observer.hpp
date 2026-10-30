#pragma once
// MVP-4: the background observer. Pure orchestration: poll a snapshot -> WatchTracker (debounced
// diff, the same one `watch` uses) -> persist events and the confirmed-state checkpoint in the
// EventStore. Everything that touches the world (snapshot, clock, waiting, stop) is injected, so
// tests drive it deterministically; the Windows service supplies real hooks and runs `run()` on
// its worker thread while the IPC thread calls `status()`.
//
// Restart semantics (events are never replayed):
//   * The confirmed state of every check is persisted after every poll (check_state table).
//   * On start the persisted state becomes the tracker's baseline and the first snapshot is
//     compared with it. Same state => no event. A difference is debounced exactly like any other
//     change (confirm_polls consecutive polls) and then recorded once, with the extra evidence
//     pair detected_after_restart=true (it happened while the service was not watching).
//   * With no persisted state (first run) the first snapshot is the baseline and yields no event.
// Store failures never stop the loop silently: they are counted (store_errors), the message kept
// (last_error), and events that could not be written are retried at the next poll (bounded queue).
#include <functional>
#include <mutex>
#include <optional>
#include <string>

#include "store.hpp"
#include "types.hpp"
#include "watch.hpp"

namespace metasec {

enum class ObserverState { Starting, Running, Stopping, Stopped };
const char* to_string(ObserverState s);

// Snapshot of the observer for the IPC server. All fields are plain values.
struct ObserverStatus {
    ObserverState state = ObserverState::Stopped;
    std::string started_utc;
    std::string last_observation_utc;  // time of the last snapshot that was read ("" = none yet)
    long long polls = 0;               // snapshots read successfully
    long long events_total = 0;        // lifetime events stored (from the store)
    long long store_errors = 0;        // failed store operations since start
    long long snapshot_errors = 0;     // snapshot hook exceptions since start
    std::string last_error;            // most recent store/snapshot error ("" = none)
    std::optional<Overall> overall;    // of the last snapshot; empty before the first poll
    std::string version;
};

struct ObserverOptions {
    int interval_seconds = kDefaultIntervalSeconds;
    int confirm_polls = kDefaultConfirmPolls;
    int max_polls = 0;  // snapshot attempts before stopping; 0 = until stop is requested
    std::string version;
};

struct ObserverHooks {
    std::function<StatusReport()> snapshot;     // one poll; may throw (counted, loop continues)
    std::function<bool(int seconds)> wait;      // false = stop requested during the wait
    std::function<bool()> stop_requested;       // polled before every snapshot
    std::function<std::string()> now_utc;       // 2026-10-30T12:34:56Z
    std::function<long long()> now_epoch;       // optional (empty = last_poll_epoch not written)
};

enum class ObserverStop { MaxPolls, Interrupted, Error };
const char* to_string(ObserverStop s);

struct ObserverResult {
    ObserverStop stop = ObserverStop::MaxPolls;
    long long polls = 0;
    long long events_recorded = 0;  // new rows written, lifecycle included (duplicates not counted)
    long long store_errors = 0;
    std::string error;  // what() of an exception from a hook other than snapshot
};

class Observer {
public:
    // `store` may be null (store unavailable): the loop still observes, every poll counts one
    // store error ("event store unavailable"), nothing is persisted. Not owned.
    Observer(EventStore* store, ObserverOptions opt, ObserverHooks hooks);

    // Blocks until max_polls, stop, or a hook throws. Records service_started at the beginning
    // and service_stopped at the end. Call once.
    ObserverResult run();

    // Thread-safe copy of the current status (any thread, at any time, also while run() is active).
    ObserverStatus status() const;

private:
    void update(const std::function<void(ObserverStatus&)>& f);
    void note_store_error(const std::string& what);

    EventStore* store_;
    ObserverOptions opt_;
    ObserverHooks hooks_;
    mutable std::mutex mu_;
    ObserverStatus status_;
};

// Pure conversion used by the observer (exposed for tests and for the service's event rendering).
StoreEvent to_store_event(const WatchEvent& e);

}  // namespace metasec
