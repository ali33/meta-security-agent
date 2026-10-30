#include "store.hpp"

#include <algorithm>
#include <cstdlib>
#include <mutex>
#include <system_error>

#include <sqlite3.h>

#include "json.hpp"

namespace metasec {

std::string truncate_utf8(const std::string& s, std::size_t max_bytes) {
    if (s.size() <= max_bytes) return s;
    std::size_t n = max_bytes;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) --n;  // s[n] is a continuation byte
    return s.substr(0, n);
}

namespace {

constexpr int kBusyTimeoutMs = 5000;
constexpr std::int64_t kReservePages = 4;  // rotation starts when fewer pages than this are left
constexpr int kMaxPruneRounds = 32;

// Ordered migration steps. Step i migrates user_version i -> i + 1. Constant SQL only.
struct Migration {
    const char* const* statements;
    std::size_t count;
};
const char* const kMigrateV1[] = {
    "CREATE TABLE events("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " kind TEXT NOT NULL,"
    " observed_at_utc TEXT NOT NULL,"
    " first_observed_at_utc TEXT NOT NULL,"
    " check_id TEXT NOT NULL,"
    " from_state TEXT NOT NULL,"
    " to_state TEXT NOT NULL,"
    " confirmations INTEGER NOT NULL,"
    " source TEXT NOT NULL,"
    " error_code TEXT NOT NULL,"
    " evidence_json TEXT NOT NULL,"
    " dedupe_key TEXT NOT NULL UNIQUE)",
    "CREATE TABLE check_state("
    " check_id TEXT PRIMARY KEY,"
    " state TEXT NOT NULL,"
    " updated_utc TEXT NOT NULL)",
    "CREATE TABLE kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
};
const Migration kMigrations[] = {{kMigrateV1, sizeof kMigrateV1 / sizeof kMigrateV1[0]}};
static_assert(sizeof kMigrations / sizeof kMigrations[0] == static_cast<std::size_t>(kStoreSchemaVersion),
              "one migration step per schema version");

std::string describe(sqlite3* db, int rc, const char* what) {
    std::string m = std::string(what) + ": ";
    const char* e = db ? sqlite3_errmsg(db) : sqlite3_errstr(rc);
    m += (e && *e) ? e : "unknown error";
    m += " (sqlite " + std::to_string(rc) + ")";
    return m;
}

bool is_full(int rc) { return (rc & 0xFF) == SQLITE_FULL; }

// Prepared statement; every value reaches SQLite through a bound parameter.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) { rc_ = sqlite3_prepare_v2(db, sql, -1, &s_, nullptr); }
    ~Stmt() { sqlite3_finalize(s_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
    int prepare_rc() const { return rc_; }
    int text(int i, const std::string& v) {
        return rc_ != SQLITE_OK ? rc_
                                : sqlite3_bind_text(s_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    }
    int i64(int i, std::int64_t v) { return rc_ != SQLITE_OK ? rc_ : sqlite3_bind_int64(s_, i, v); }
    int step() { return rc_ != SQLITE_OK ? rc_ : sqlite3_step(s_); }
    std::string col_text(int i) const {
        const unsigned char* t = sqlite3_column_text(s_, i);
        return t ? std::string(reinterpret_cast<const char*>(t), static_cast<std::size_t>(sqlite3_column_bytes(s_, i)))
                 : std::string();
    }
    std::int64_t col_i64(int i) const { return sqlite3_column_int64(s_, i); }

private:
    sqlite3_stmt* s_ = nullptr;
    int rc_ = SQLITE_OK;
};

std::string evidence_to_json(const EvidencePairs& ev) {
    std::string o = "{";
    for (std::size_t i = 0; i < ev.size(); ++i) {
        if (i) o += ',';
        o += '"' + json_escape(ev[i].first) + "\":\"" + json_escape(ev[i].second) + '"';
    }
    return o + "}";
}

// Truncates every field and derives the dedupe key. The store only ever sees the result.
StoreEvent normalize(const StoreEvent& e) {
    StoreEvent n;
    n.kind = truncate_utf8(e.kind, kStoreMaxKind);
    n.observed_at_utc = truncate_utf8(e.observed_at_utc, kStoreMaxTimestamp);
    n.first_observed_at_utc = truncate_utf8(e.first_observed_at_utc, kStoreMaxTimestamp);
    n.check_id = truncate_utf8(e.check_id, kStoreMaxId);
    n.from_state = truncate_utf8(e.from_state, kStoreMaxState);
    n.to_state = truncate_utf8(e.to_state, kStoreMaxState);
    n.confirmations = e.confirmations < 0 ? 0 : e.confirmations;
    n.source = truncate_utf8(e.source, kStoreMaxId);
    n.error_code = truncate_utf8(e.error_code, kStoreMaxId);
    for (const auto& [k, v] : e.evidence) {
        if (n.evidence.size() >= kStoreMaxEvidencePairs) break;
        std::string key = truncate_utf8(k, kStoreMaxEvidenceKey);
        bool dup = false;  // truncation can make two keys equal; JSON objects need unique keys
        for (const auto& p : n.evidence) dup = dup || p.first == key;
        if (!dup) n.evidence.emplace_back(std::move(key), truncate_utf8(v, kStoreMaxEvidenceValue));
    }
    if (e.dedupe_key.empty()) {
        n.dedupe_key = n.kind + '|' + n.check_id + '|' + n.from_state + '|' + n.to_state + '|' +
                       (n.first_observed_at_utc.empty() ? n.observed_at_utc : n.first_observed_at_utc);
    } else {
        n.dedupe_key = e.dedupe_key;
    }
    n.dedupe_key = truncate_utf8(n.dedupe_key, kStoreMaxDedupeKey);
    return n;
}

}  // namespace

struct EventStore::Impl {
    std::filesystem::path path;
    StoreLimits limits;
    sqlite3* db = nullptr;
    std::int64_t page_size = 4096;
    std::mutex mu;

    ~Impl() {
        if (db) sqlite3_close(db);
    }

    int exec(const char* sql) { return sqlite3_exec(db, sql, nullptr, nullptr, nullptr); }

    // PRAGMA name (constant, chosen by this file) returning one integer.
    std::int64_t pragma_int(const char* sql, int* rc_out = nullptr) {
        Stmt s(db, sql);
        int rc = s.prepare_rc();
        std::int64_t v = 0;
        if (rc == SQLITE_OK) {
            rc = s.step();
            if (rc == SQLITE_ROW) {
                v = s.col_i64(0);
                rc = SQLITE_OK;
            }
        }
        if (rc_out) *rc_out = rc;
        return v;
    }

    std::int64_t limit_pages() const { return std::max<std::int64_t>(limits.max_bytes / page_size, 1); }

    std::int64_t row_count() {
        Stmt s(db, "SELECT COUNT(*) FROM events");
        return s.step() == SQLITE_ROW ? s.col_i64(0) : 0;
    }

    std::int64_t used_pages() { return pragma_int("PRAGMA page_count") - pragma_int("PRAGMA freelist_count"); }

    // Deletes the `n` oldest rows (never the newest). Returns the number deleted.
    std::int64_t prune_oldest(std::int64_t n) {
        const std::int64_t rows = row_count();
        n = std::min(n, rows - 1);
        if (n <= 0) return 0;
        Stmt s(db, "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?1)");
        if (s.i64(1, n) != SQLITE_OK || s.step() != SQLITE_DONE) return 0;
        return sqlite3_changes(db);
    }

    // Rotation policy (see header). Returns rows pruned.
    std::int64_t enforce_quota() {
        std::int64_t pruned = 0;
        const std::int64_t hysteresis = std::min<std::int64_t>(limits.prune_batch, limits.max_rows / 2);
        for (int round = 0; round < kMaxPruneRounds; ++round) {
            const std::int64_t rows = row_count();
            const bool too_many = rows > limits.max_rows;
            const bool too_big = used_pages() + kReservePages > limit_pages();
            if ((!too_many && !too_big) || rows <= 1) break;
            std::int64_t n = 0;
            if (too_many) n = rows - (limits.max_rows - hysteresis);
            if (too_big) n = std::max<std::int64_t>({n, limits.prune_batch, rows / 10});
            const std::int64_t done = prune_oldest(std::max<std::int64_t>(n, 1));
            if (done == 0) break;
            pruned += done;
        }
        return pruned;
    }

    struct Commit {
        bool ok = false;
        std::string error;
        int stored = 0;
        int duplicates = 0;
        std::int64_t pruned = 0;
        std::vector<std::int64_t> ids;  // 0 = duplicate
    };

    // One transaction: events + optional check_state replacement + kv. Retries once after pruning
    // when SQLite reports the file is full.
    Commit commit(const std::vector<StoreEvent>& events, const std::vector<CheckStateRow>* states,
                  const std::string* observation_utc, long long epoch, const std::string* started_utc) {
        Commit out;
        std::vector<StoreEvent> norm;
        norm.reserve(events.size());
        for (const auto& e : events) norm.push_back(normalize(e));

        int rc = SQLITE_OK;
        const char* stage = "write";
        for (int attempt = 0; attempt < 2; ++attempt) {
            out.stored = out.duplicates = 0;
            out.ids.clear();
            rc = exec("BEGIN IMMEDIATE");
            stage = "begin transaction";
            if (rc == SQLITE_OK) {
                rc = body(norm, states, observation_utc, epoch, started_utc, out, stage);
            }
            if (rc == SQLITE_OK) {
                stage = "commit";
                rc = exec("COMMIT");
            }
            if (rc == SQLITE_OK) break;
            const std::string msg = describe(db, rc, stage);
            exec("ROLLBACK");  // no-op if no transaction is active
            if (attempt == 0 && is_full(rc)) {
                const std::int64_t rows = row_count();
                out.pruned += prune_oldest(std::max<std::int64_t>(limits.prune_batch, rows / 4));
                continue;
            }
            out.ok = false;
            out.error = is_full(rc) ? "event store is full even after pruning old events; the new data was NOT stored (" + msg + ")"
                                    : msg;
            return out;
        }
        out.ok = true;
        out.pruned += enforce_quota();
        return out;
    }

    int body(const std::vector<StoreEvent>& norm, const std::vector<CheckStateRow>* states,
             const std::string* observation_utc, long long epoch, const std::string* started_utc, Commit& out,
             const char*& stage) {
        stage = "insert event";
        for (const auto& e : norm) {
            Stmt s(db,
                   "INSERT OR IGNORE INTO events(kind, observed_at_utc, first_observed_at_utc, check_id, from_state,"
                   " to_state, confirmations, source, error_code, evidence_json, dedupe_key)"
                   " VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)");
            int rc = s.prepare_rc();
            auto b = [&](int r) { if (rc == SQLITE_OK) rc = r; };
            b(s.text(1, e.kind));
            b(s.text(2, e.observed_at_utc));
            b(s.text(3, e.first_observed_at_utc));
            b(s.text(4, e.check_id));
            b(s.text(5, e.from_state));
            b(s.text(6, e.to_state));
            b(s.i64(7, e.confirmations));
            b(s.text(8, e.source));
            b(s.text(9, e.error_code));
            b(s.text(10, evidence_to_json(e.evidence)));
            b(s.text(11, e.dedupe_key));
            if (rc == SQLITE_OK) {
                rc = s.step();
                if (rc == SQLITE_DONE) rc = SQLITE_OK;
            }
            if (rc != SQLITE_OK) return rc;
            if (sqlite3_changes(db) > 0) {
                ++out.stored;
                out.ids.push_back(sqlite3_last_insert_rowid(db));
            } else {
                ++out.duplicates;
                out.ids.push_back(0);
            }
        }
        if (out.stored > 0) {
            stage = "update event counter";
            Stmt s(db,
                   "INSERT INTO kv(key, value) VALUES(?1, CAST(?2 AS TEXT))"
                   " ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + ?2 AS TEXT)");
            int rc = s.prepare_rc();
            if (rc == SQLITE_OK) rc = s.text(1, kKvEventsTotal);
            if (rc == SQLITE_OK) rc = s.i64(2, out.stored);
            if (rc == SQLITE_OK) rc = s.step();
            if (rc != SQLITE_DONE) return rc == SQLITE_OK ? SQLITE_ERROR : rc;
        }
        if (states) {
            stage = "save check state";
            int rc = exec("DELETE FROM check_state");
            if (rc != SQLITE_OK) return rc;
            for (const auto& r : *states) {
                Stmt s(db, "INSERT OR REPLACE INTO check_state(check_id, state, updated_utc) VALUES(?1, ?2, ?3)");
                rc = s.prepare_rc();
                if (rc == SQLITE_OK) rc = s.text(1, truncate_utf8(r.check_id, kStoreMaxId));
                if (rc == SQLITE_OK) rc = s.text(2, truncate_utf8(r.state, kStoreMaxState));
                if (rc == SQLITE_OK) rc = s.text(3, truncate_utf8(r.updated_utc, kStoreMaxTimestamp));
                if (rc == SQLITE_OK) rc = s.step();
                if (rc != SQLITE_DONE) return rc == SQLITE_OK ? SQLITE_ERROR : rc;
            }
        }
        stage = "update checkpoint";
        if (observation_utc) {
            const int rc = put_kv(kKvLastObservationUtc, *observation_utc);
            if (rc != SQLITE_OK) return rc;
        }
        if (epoch >= 0) {
            const int rc = put_kv(kKvLastPollEpoch, std::to_string(epoch));
            if (rc != SQLITE_OK) return rc;
        }
        if (started_utc) {
            const int rc = put_kv(kKvServiceStartedUtc, *started_utc);
            if (rc != SQLITE_OK) return rc;
        }
        return SQLITE_OK;
    }

    int put_kv(const std::string& key, const std::string& value) {
        Stmt s(db, "INSERT OR REPLACE INTO kv(key, value) VALUES(?1, ?2)");
        int rc = s.prepare_rc();
        if (rc == SQLITE_OK) rc = s.text(1, truncate_utf8(key, kStoreMaxKvKey));
        if (rc == SQLITE_OK) rc = s.text(2, truncate_utf8(value, kStoreMaxKvValue));
        if (rc == SQLITE_OK) rc = s.step();
        return rc == SQLITE_DONE ? SQLITE_OK : (rc == SQLITE_OK ? SQLITE_ERROR : rc);
    }
};

EventStore::EventStore(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
EventStore::EventStore(EventStore&&) noexcept = default;
EventStore& EventStore::operator=(EventStore&&) noexcept = default;
EventStore::~EventStore() = default;

const std::filesystem::path& EventStore::path() const { return impl_->path; }

namespace {

StoreOpen open_fail(std::string e) {
    StoreOpen o;
    o.error = std::move(e);
    return o;
}

}  // namespace

StoreOpen EventStore::open(const std::filesystem::path& path, const StoreLimits& requested) {
    try {
        auto impl = std::make_unique<Impl>();
        impl->path = path;
        impl->limits = requested;
        StoreLimits& lim = impl->limits;
        if (lim.max_rows < 1) lim.max_rows = 1;
        if (lim.max_bytes < kStoreMinBytes) lim.max_bytes = kStoreMinBytes;
        if (lim.prune_batch < 1) lim.prune_batch = 1;

        std::error_code ec;
        if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) return open_fail("cannot create event store directory: " + ec.message());

        const std::u8string u8 = path.u8string();
        const std::string utf8(u8.begin(), u8.end());
        int rc = sqlite3_open_v2(utf8.c_str(), &impl->db,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rc != SQLITE_OK) return open_fail(describe(impl->db, rc, "cannot open event store"));
        sqlite3* db = impl->db;
        sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
        sqlite3_busy_timeout(db, kBusyTimeoutMs);

        // The first statement that reads the file is where a garbage file is detected.
        const char* const pragmas[] = {"PRAGMA trusted_schema=OFF", "PRAGMA journal_mode=DELETE",
                                       "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON",
                                       "PRAGMA temp_store=MEMORY"};
        for (const char* p : pragmas) {
            rc = impl->exec(p);
            if (rc != SQLITE_OK) return open_fail(describe(db, rc, "cannot configure event store"));
        }

        int vrc = SQLITE_OK;
        const std::int64_t version = impl->pragma_int("PRAGMA user_version", &vrc);
        if (vrc != SQLITE_OK) return open_fail(describe(db, vrc, "cannot read event store"));
        if (version < 0 || version > kStoreSchemaVersion)
            return open_fail("event store schema version " + std::to_string(version) +
                             " is newer than supported " + std::to_string(kStoreSchemaVersion) +
                             "; refusing to open (upgrade META Security Agent)");

        if (version < kStoreSchemaVersion) {
            rc = impl->exec("BEGIN IMMEDIATE");
            if (rc != SQLITE_OK) return open_fail(describe(db, rc, "cannot migrate event store"));
            for (std::int64_t v = version; v < kStoreSchemaVersion && rc == SQLITE_OK; ++v) {
                const Migration& m = kMigrations[static_cast<std::size_t>(v)];
                for (std::size_t i = 0; i < m.count && rc == SQLITE_OK; ++i) rc = impl->exec(m.statements[i]);
                if (rc == SQLITE_OK) {
                    // PRAGMA cannot take bound parameters; the value is a compile-time version number.
                    const std::string set = "PRAGMA user_version=" + std::to_string(v + 1);
                    rc = impl->exec(set.c_str());
                }
            }
            if (rc == SQLITE_OK) rc = impl->exec("COMMIT");
            if (rc != SQLITE_OK) {
                const std::string msg = describe(db, rc, "cannot migrate event store");
                impl->exec("ROLLBACK");
                return open_fail(msg);
            }
        }

        impl->page_size = impl->pragma_int("PRAGMA page_size");
        if (impl->page_size <= 0) impl->page_size = 4096;

        // Never let the file exceed the cap. A file already over a (newly lowered) cap is pruned
        // and compacted first, because max_page_count cannot go below the current size.
        for (int round = 0; round < 8 && impl->pragma_int("PRAGMA page_count") > impl->limit_pages(); ++round) {
            impl->prune_oldest(std::max<std::int64_t>(impl->row_count() / 2, 1));
            impl->exec("VACUUM");
        }
        if (impl->pragma_int("PRAGMA page_count") > impl->limit_pages())
            return open_fail("event store file is larger than the configured size cap and could not be compacted");
        const std::string cap = "PRAGMA max_page_count=" + std::to_string(impl->limit_pages());
        rc = impl->exec(cap.c_str());
        if (rc != SQLITE_OK) return open_fail(describe(db, rc, "cannot cap event store size"));

        impl->enforce_quota();

        StoreOpen o;
        o.ok = true;
        o.store.reset(new EventStore(std::move(impl)));
        return o;
    } catch (const std::exception& e) {
        return open_fail(std::string("cannot open event store: ") + e.what());
    }
}

AppendResult EventStore::append_event(const StoreEvent& e) {
    AppendResult r;
    if (!impl_ || !impl_->db) {
        r.error = "event store is closed";
        return r;
    }
    try {
        std::lock_guard lock(impl_->mu);
        const auto c = impl_->commit({e}, nullptr, nullptr, -1, nullptr);
        r.pruned = c.pruned;
        if (!c.ok) {
            r.error = c.error;
            return r;
        }
        r.status = c.stored > 0 ? AppendStatus::Stored : AppendStatus::Duplicate;
        r.id = c.ids.empty() ? 0 : c.ids[0];
    } catch (const std::exception& ex) {
        r.status = AppendStatus::Failed;
        r.error = std::string("event store error: ") + ex.what();
    }
    return r;
}

AppendResult EventStore::record_lifecycle(const std::string& kind, const std::string& utc) {
    AppendResult r;
    if (kind != kLifecycleStarted && kind != kLifecycleStopped) {
        r.error = "unsupported lifecycle kind";
        return r;
    }
    if (!impl_ || !impl_->db) {
        r.error = "event store is closed";
        return r;
    }
    StoreEvent e;
    e.kind = kind;
    e.observed_at_utc = utc;
    e.first_observed_at_utc = utc;
    e.source = "service";
    e.confirmations = 1;
    e.dedupe_key = kind + '|' + truncate_utf8(utc, kStoreMaxTimestamp);
    try {
        std::lock_guard lock(impl_->mu);
        const std::string started = truncate_utf8(utc, kStoreMaxTimestamp);
        const auto c = impl_->commit({e}, nullptr, nullptr, -1, kind == kLifecycleStarted ? &started : nullptr);
        r.pruned = c.pruned;
        if (!c.ok) {
            r.error = c.error;
            return r;
        }
        r.status = c.stored > 0 ? AppendStatus::Stored : AppendStatus::Duplicate;
        r.id = c.ids.empty() ? 0 : c.ids[0];
    } catch (const std::exception& ex) {
        r.status = AppendStatus::Failed;
        r.error = std::string("event store error: ") + ex.what();
    }
    return r;
}

PollCommit EventStore::record_poll(const std::vector<StoreEvent>& events, const std::vector<CheckStateRow>& states,
                                   const std::string& observation_utc, long long epoch) {
    PollCommit p;
    if (!impl_ || !impl_->db) {
        p.error = "event store is closed";
        return p;
    }
    try {
        std::lock_guard lock(impl_->mu);
        const auto c = impl_->commit(events, &states, &observation_utc, epoch, nullptr);
        p.ok = c.ok;
        p.error = c.error;
        p.stored = c.stored;
        p.duplicates = c.duplicates;
        p.pruned = c.pruned;
    } catch (const std::exception& ex) {
        p.ok = false;
        p.error = std::string("event store error: ") + ex.what();
    }
    return p;
}

// Read helpers share one shape: lock, run, convert exceptions to an error value.
#define METASEC_STORE_GUARD(T, body)                                                    \
    StoreResult<T> r;                                                                   \
    if (!impl_ || !impl_->db) {                                                         \
        r.error = "event store is closed";                                              \
        return r;                                                                       \
    }                                                                                   \
    try {                                                                               \
        std::lock_guard lock(impl_->mu);                                                \
        body                                                                            \
    } catch (const std::exception& ex) {                                                \
        r.ok = false;                                                                   \
        r.error = std::string("event store error: ") + ex.what();                       \
    }                                                                                   \
    return r;

StoreResult<std::vector<StoredEvent>> EventStore::recent_events(int limit) {
    METASEC_STORE_GUARD(std::vector<StoredEvent>, {
        const int n = std::clamp(limit, 1, kStoreMaxRecentEvents);
        Stmt s(impl_->db,
               "SELECT id, kind, observed_at_utc, first_observed_at_utc, check_id, from_state, to_state,"
               " confirmations, source, error_code, evidence_json FROM events ORDER BY id DESC LIMIT ?1");
        int rc = s.prepare_rc();
        if (rc == SQLITE_OK) rc = s.i64(1, n);
        while (rc == SQLITE_OK && (rc = s.step()) == SQLITE_ROW) {
            StoredEvent e;
            e.id = s.col_i64(0);
            e.kind = s.col_text(1);
            e.observed_at_utc = s.col_text(2);
            e.first_observed_at_utc = s.col_text(3);
            e.check_id = s.col_text(4);
            e.from_state = s.col_text(5);
            e.to_state = s.col_text(6);
            e.confirmations = static_cast<int>(s.col_i64(7));
            e.source = s.col_text(8);
            e.error_code = s.col_text(9);
            const JsonParseResult ev = json_parse(s.col_text(10), 4);
            e.evidence_valid = ev.ok && ev.value.type == JsonValue::Type::Object;
            if (e.evidence_valid) {
                for (const auto& [k, v] : ev.value.object) {
                    if (v.type != JsonValue::Type::String) {
                        e.evidence_valid = false;
                        e.evidence.clear();
                        break;
                    }
                    e.evidence.emplace_back(k, v.string);
                }
            }
            r.value.push_back(std::move(e));
            rc = SQLITE_OK;
        }
        if (rc == SQLITE_DONE) {
            r.ok = true;
        } else {
            r.value.clear();
            r.error = describe(impl_->db, rc, "cannot read events");
        }
    })
}

StoreResult<std::int64_t> EventStore::count_events() {
    METASEC_STORE_GUARD(std::int64_t, {
        Stmt s(impl_->db, "SELECT COUNT(*) FROM events");
        const int rc = s.step();
        if (rc == SQLITE_ROW) {
            r.ok = true;
            r.value = s.col_i64(0);
        } else {
            r.error = describe(impl_->db, rc, "cannot count events");
        }
    })
}

StoreResult<StoreStats> EventStore::stats() {
    METASEC_STORE_GUARD(StoreStats, {
        int rc = SQLITE_OK;
        r.value.rows = impl_->row_count();
        r.value.db_bytes = impl_->pragma_int("PRAGMA page_count", &rc) * impl_->page_size;
        r.value.schema_version = static_cast<int>(impl_->pragma_int("PRAGMA user_version"));
        Stmt s(impl_->db, "SELECT value FROM kv WHERE key = ?1");
        if (rc == SQLITE_OK) rc = s.text(1, kKvEventsTotal);
        if (rc == SQLITE_OK) {
            rc = s.step();
            if (rc == SQLITE_ROW) {
                r.value.events_total = std::strtoll(s.col_text(0).c_str(), nullptr, 10);
                rc = SQLITE_DONE;
            }
        }
        if (rc == SQLITE_DONE) {
            r.ok = true;
        } else {
            r.error = describe(impl_->db, rc, "cannot read store statistics");
        }
    })
}

StoreResult<std::vector<CheckStateRow>> EventStore::load_check_states() {
    METASEC_STORE_GUARD(std::vector<CheckStateRow>, {
        Stmt s(impl_->db, "SELECT check_id, state, updated_utc FROM check_state ORDER BY check_id");
        int rc = s.prepare_rc();
        while (rc == SQLITE_OK && (rc = s.step()) == SQLITE_ROW) {
            r.value.push_back({s.col_text(0), s.col_text(1), s.col_text(2)});
            rc = SQLITE_OK;
        }
        if (rc == SQLITE_DONE) {
            r.ok = true;
        } else {
            r.value.clear();
            r.error = describe(impl_->db, rc, "cannot read check state");
        }
    })
}

StoreResult<bool> EventStore::save_check_states(const std::vector<CheckStateRow>& rows) {
    METASEC_STORE_GUARD(bool, {
        const auto c = impl_->commit({}, &rows, nullptr, -1, nullptr);
        r.ok = c.ok;
        r.error = c.error;
        r.value = c.ok;
    })
}

StoreResult<std::optional<std::string>> EventStore::get_kv(const std::string& key) {
    METASEC_STORE_GUARD(std::optional<std::string>, {
        Stmt s(impl_->db, "SELECT value FROM kv WHERE key = ?1");
        int rc = s.prepare_rc();
        if (rc == SQLITE_OK) rc = s.text(1, truncate_utf8(key, kStoreMaxKvKey));
        if (rc == SQLITE_OK) rc = s.step();
        if (rc == SQLITE_ROW) {
            r.ok = true;
            r.value = s.col_text(0);
        } else if (rc == SQLITE_DONE) {
            r.ok = true;
        } else {
            r.error = describe(impl_->db, rc, "cannot read value");
        }
    })
}

StoreResult<std::optional<std::string>> EventStore::last_observation_utc() { return get_kv(kKvLastObservationUtc); }

StoreResult<bool> EventStore::set_kv(const std::string& key, const std::string& value) {
    METASEC_STORE_GUARD(bool, {
        int rc = impl_->exec("BEGIN IMMEDIATE");
        if (rc == SQLITE_OK) rc = impl_->put_kv(key, value);
        if (rc == SQLITE_OK) rc = impl_->exec("COMMIT");
        if (rc == SQLITE_OK) {
            r.ok = true;
            r.value = true;
        } else {
            r.error = is_full(rc) ? "event store is full; value was NOT stored" : describe(impl_->db, rc, "cannot store value");
            impl_->exec("ROLLBACK");
        }
    })
}

}  // namespace metasec
