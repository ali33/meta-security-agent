#pragma once
// MVP-4: local event store (SQLite). The only part of the OS-independent core that touches a file.
//
// What is stored: small, already-redacted facts the watch events carry (check id, old/new state,
// timestamps, a few short key/value evidence pairs). NEVER file content, never secrets, never
// credentials. Every text field is truncated to the limits below before it is written.
//
// Failure model: expected failures (unwritable path, corrupt file, newer schema, disk full) are
// returned as values with a human-readable `error`; nothing here throws for them. A store that
// cannot be opened is a closed store: the caller decides (the service keeps observing and
// reports `store_errors`; it never silently pretends events were saved).
//
// Schema (PRAGMA user_version = kStoreSchemaVersion):
//   events(id INTEGER PRIMARY KEY AUTOINCREMENT, kind, observed_at_utc, first_observed_at_utc,
//          check_id, from_state, to_state, confirmations, source, error_code, evidence_json,
//          dedupe_key UNIQUE)
//   check_state(check_id PRIMARY KEY, state, updated_utc)  -- last CONFIRMED state per check:
//          the checkpoint the observer loads after a restart (events are never replayed)
//   kv(key PRIMARY KEY, value)  -- last_observation_utc, last_poll_epoch, service_started_utc,
//          events_total (lifetime counter of stored events, survives rotation)
// Migrations are ordered steps (v0 empty -> v1 ...), each run in one transaction. A database whose
// user_version is NEWER than this build supports is refused (fail closed), never downgraded.
//
// Idempotence: every event has a dedupe_key (derived from kind, check, from, to and the time the
// new value was first seen when the caller leaves it empty). INSERT OR IGNORE makes the same event
// appended twice (e.g. after a crash and restart) a single row.
//
// Rotation policy (quota): after every write, if rows > max_rows, or the database no longer has
// room (used pages within a few pages of max_bytes), the OLDEST rows (lowest id) are deleted in
// batches of `prune_batch` (at least enough to get back under the cap with hysteresis). The newest
// row is never pruned by rotation. In addition PRAGMA max_page_count caps the file so it can never
// exceed max_bytes, whatever happens. If a write hits SQLITE_FULL anyway, it is rolled back, the
// oldest rows are pruned and the write is retried ONCE; if it still fails the result is
// AppendStatus::Failed with a clear error (the NEWEST event is never dropped silently: the caller
// is told). Pruned rows are counted in the result.
//
// Thread safety: all methods may be called from several threads (internally serialized by one
// mutex); the observer thread writes while the IPC thread reads.
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace metasec {

inline constexpr int kStoreSchemaVersion = 1;

// Hard maxima of stored text (bytes, cut on a UTF-8 boundary).
inline constexpr std::size_t kStoreMaxKind = 32;
inline constexpr std::size_t kStoreMaxTimestamp = 40;
inline constexpr std::size_t kStoreMaxId = 128;       // check_id, source, error_code
inline constexpr std::size_t kStoreMaxState = 32;
inline constexpr std::size_t kStoreMaxEvidenceKey = 64;
inline constexpr std::size_t kStoreMaxEvidenceValue = 256;
inline constexpr std::size_t kStoreMaxEvidencePairs = 16;
inline constexpr std::size_t kStoreMaxDedupeKey = 512;
inline constexpr std::size_t kStoreMaxKvKey = 64;
inline constexpr std::size_t kStoreMaxKvValue = 256;

inline constexpr int kStoreMaxRecentEvents = 500;
inline constexpr std::int64_t kStoreMinBytes = 256 * 1024;  // smaller caps are raised to this

// kv keys used by the service.
inline constexpr const char* kKvLastObservationUtc = "last_observation_utc";
inline constexpr const char* kKvLastPollEpoch = "last_poll_epoch";
inline constexpr const char* kKvServiceStartedUtc = "service_started_utc";
inline constexpr const char* kKvEventsTotal = "events_total";

// Lifecycle event kinds accepted by record_lifecycle.
inline constexpr const char* kLifecycleStarted = "service_started";
inline constexpr const char* kLifecycleStopped = "service_stopped";

struct StoreLimits {
    std::int64_t max_rows = 10000;
    std::int64_t max_bytes = 16LL * 1024 * 1024;  // raised to kStoreMinBytes if smaller
    int prune_batch = 500;                        // rows deleted per rotation step (>= 1)
};

using EvidencePairs = std::vector<std::pair<std::string, std::string>>;

// An event to store. States are the to_string(State) names; empty = absent (check added/removed).
struct StoreEvent {
    std::string kind;  // "change", "observation_lost", ..., "service_started", "service_stopped"
    std::string observed_at_utc;
    std::string first_observed_at_utc;
    std::string check_id;
    std::string from_state;
    std::string to_state;
    int confirmations = 0;
    std::string source;
    std::string error_code;
    EvidencePairs evidence;
    std::string dedupe_key;  // empty = derived (see "Idempotence")
};

struct StoredEvent {
    std::int64_t id = 0;
    std::string kind, observed_at_utc, first_observed_at_utc, check_id, from_state, to_state;
    int confirmations = 0;
    std::string source, error_code;
    EvidencePairs evidence;  // empty (and evidence_valid=false) if the stored JSON is malformed
    bool evidence_valid = true;
};

struct CheckStateRow {
    std::string check_id;
    std::string state;  // to_string(State)
    std::string updated_utc;
};

enum class AppendStatus {
    Stored,     // new row written
    Duplicate,  // same dedupe_key already stored: nothing written (idempotent success)
    Failed,     // NOT stored; `error` says why (disk full after pruning, I/O error, closed store)
};

struct AppendResult {
    AppendStatus status = AppendStatus::Failed;
    std::string error;
    std::int64_t id = 0;      // rowid when Stored
    std::int64_t pruned = 0;  // rows removed by rotation during this call
    bool ok() const { return status != AppendStatus::Failed; }
};

struct PollCommit {
    bool ok = false;
    std::string error;
    int stored = 0;
    int duplicates = 0;
    std::int64_t pruned = 0;
};

struct StoreStats {
    std::int64_t rows = 0;          // events currently retained
    std::int64_t events_total = 0;  // lifetime counter (kv events_total)
    std::int64_t db_bytes = 0;      // page_count * page_size (file size)
    int schema_version = 0;
};

template <class T>
struct StoreResult {
    bool ok = false;
    std::string error;
    T value{};
};

class EventStore;
struct StoreOpen;

class EventStore {
public:
    EventStore(const EventStore&) = delete;
    EventStore& operator=(const EventStore&) = delete;
    EventStore(EventStore&&) noexcept;
    EventStore& operator=(EventStore&&) noexcept;
    ~EventStore();

    // Opens (creating file and parent directory if needed), configures and migrates. Never throws.
    // Prefer this over a constructor so failure is a value.
    static StoreOpen open(const std::filesystem::path& path, const StoreLimits& limits = {});

    // --- events ---
    AppendResult append_event(const StoreEvent& e);
    // kind must be kLifecycleStarted or kLifecycleStopped. service_started also sets the kv
    // service_started_utc.
    AppendResult record_lifecycle(const std::string& kind, const std::string& utc);
    // One atomic transaction per poll: appends `events` (idempotent), replaces check_state with
    // `states` (the confirmed state after this poll), sets last_observation_utc / last_poll_epoch.
    // Either everything is committed or nothing is. `epoch` < 0 = leave last_poll_epoch alone.
    PollCommit record_poll(const std::vector<StoreEvent>& events, const std::vector<CheckStateRow>& states,
                           const std::string& observation_utc, long long epoch);

    // Newest first. `limit` is clamped to 1..kStoreMaxRecentEvents.
    StoreResult<std::vector<StoredEvent>> recent_events(int limit);
    StoreResult<std::int64_t> count_events();
    StoreResult<StoreStats> stats();

    // --- checkpoint ---
    StoreResult<std::vector<CheckStateRow>> load_check_states();
    StoreResult<bool> save_check_states(const std::vector<CheckStateRow>& rows);
    StoreResult<std::optional<std::string>> last_observation_utc();

    // --- kv (key/value truncated to kStoreMaxKvKey / kStoreMaxKvValue) ---
    StoreResult<bool> set_kv(const std::string& key, const std::string& value);
    StoreResult<std::optional<std::string>> get_kv(const std::string& key);

    const std::filesystem::path& path() const;

private:
    struct Impl;
    explicit EventStore(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

struct StoreOpen {
    bool ok = false;
    std::string error;  // e.g. "event store schema version 7 is newer than supported 1; refusing to open"
    std::unique_ptr<EventStore> store;  // set only when ok
};

// Cuts `s` to at most `max_bytes` without splitting a UTF-8 sequence.
std::string truncate_utf8(const std::string& s, std::size_t max_bytes);

}  // namespace metasec
