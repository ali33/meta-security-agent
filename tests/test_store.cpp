// Tests for MVP-4 event store (SQLite): migrations, fail-closed refusals, idempotence, restart,
// rotation by rows and by bytes, truncation, ordering. Every test uses its own temp directory.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "core/store.hpp"
#include "temp_dir.hpp"

using namespace metasec;
namespace fs = std::filesystem;
using test_support::TempDir;

namespace {

int g_checks = 0;
int g_failed = 0;

void check(bool ok, const char* expr, const char* file, int line) {
    ++g_checks;
    if (!ok) {
        ++g_failed;
        std::fprintf(stderr, "FAIL %s:%d  %s\n", file, line, expr);
    }
}
#define CHECK(e) check((e), #e, __FILE__, __LINE__)

StoreEvent ev(int i, std::size_t evidence_value_len = 8, int pairs = 1) {
    StoreEvent e;
    e.kind = "change";
    e.observed_at_utc = "2026-10-30T00:00:" + std::to_string(10 + i % 50) + "Z";
    e.first_observed_at_utc = "2026-10-30T00:00:00Z";
    e.check_id = "firewall.public." + std::to_string(i);
    e.from_state = "ENABLED";
    e.to_state = "DISABLED";
    e.confirmations = 2;
    e.source = "fake";
    for (int p = 0; p < pairs; ++p)
        e.evidence.emplace_back("k" + std::to_string(p), std::string(evidence_value_len, static_cast<char>('a' + p % 26)));
    return e;
}

EventStore& open_ok(StoreOpen& o) { return *o.store; }

void test_migration_and_basics() {
    TempDir t;
    StoreOpen o = EventStore::open(t.dir() / "nested" / "dir" / "events.db");  // parent is created
    CHECK(o.ok);
    CHECK(o.error.empty());
    if (!o.ok) return;
    const auto st = o.store->stats();
    CHECK(st.ok);
    CHECK(st.value.schema_version == kStoreSchemaVersion);
    CHECK(st.value.rows == 0);
    CHECK(st.value.events_total == 0);
    CHECK(st.value.db_bytes > 0);
    CHECK(o.store->recent_events(10).ok);
    CHECK(o.store->recent_events(10).value.empty());
    CHECK(o.store->load_check_states().ok);
    CHECK(o.store->load_check_states().value.empty());
    CHECK(!o.store->last_observation_utc().value.has_value());
    CHECK(o.store->last_observation_utc().ok);
}

void test_existing_empty_v0_database_is_migrated() {
    TempDir t;
    {  // A valid SQLite file that was never used by us: user_version 0, no tables.
        sqlite3* db = nullptr;
        CHECK(sqlite3_open(t.file().string().c_str(), &db) == SQLITE_OK);
        CHECK(sqlite3_exec(db, "PRAGMA application_id=0", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
    }
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (o.ok) CHECK(o.store->stats().value.schema_version == kStoreSchemaVersion);
}

void test_foreign_database_with_same_table_is_refused() {
    TempDir t;
    {
        sqlite3* db = nullptr;
        CHECK(sqlite3_open(t.file().string().c_str(), &db) == SQLITE_OK);
        CHECK(sqlite3_exec(db, "CREATE TABLE events(x INTEGER)", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
    }
    StoreOpen o = EventStore::open(t.file());
    CHECK(!o.ok);
    CHECK(!o.error.empty());
    CHECK(!o.store);
}

void test_newer_schema_is_refused() {
    TempDir t;
    {
        StoreOpen o = EventStore::open(t.file());
        CHECK(o.ok);
        if (o.ok) CHECK(o.store->append_event(ev(1)).ok());
    }
    {
        sqlite3* db = nullptr;
        CHECK(sqlite3_open(t.file().string().c_str(), &db) == SQLITE_OK);
        CHECK(sqlite3_exec(db, "PRAGMA user_version=99", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
    }
    StoreOpen o = EventStore::open(t.file());
    CHECK(!o.ok);
    CHECK(o.error.find("newer than supported") != std::string::npos);
    CHECK(o.error.find("99") != std::string::npos);
    CHECK(!o.store);
    // The refused file is untouched: still version 99, data still there.
    sqlite3* db = nullptr;
    CHECK(sqlite3_open(t.file().string().c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* s = nullptr;
    CHECK(sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &s, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(s) == SQLITE_ROW);
    CHECK(sqlite3_column_int(s, 0) == 99);
    sqlite3_finalize(s);
    sqlite3_close(db);
}

void test_garbage_file_is_clean_error() {
    TempDir t;
    {
        std::ofstream f(t.file(), std::ios::binary);
        for (int i = 0; i < 300; ++i) f << "this is definitely not a sqlite database file ";
    }
    StoreOpen o = EventStore::open(t.file());
    CHECK(!o.ok);
    CHECK(!o.error.empty());
    CHECK(!o.store);
    // Unwritable location: parent "directory" is a regular file.
    StoreOpen o2 = EventStore::open(t.file() / "sub" / "events.db");
    CHECK(!o2.ok);
    CHECK(!o2.error.empty());
}

void test_idempotent_append() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    const AppendResult a = s.append_event(ev(1));
    CHECK(a.status == AppendStatus::Stored);
    CHECK(a.id > 0);
    const AppendResult b = s.append_event(ev(1));
    CHECK(b.status == AppendStatus::Duplicate);
    CHECK(b.ok());
    CHECK(s.count_events().value == 1);
    CHECK(s.stats().value.events_total == 1);
    // A different first-seen time is a different event.
    StoreEvent e2 = ev(1);
    e2.first_observed_at_utc = "2026-10-30T00:05:00Z";
    CHECK(s.append_event(e2).status == AppendStatus::Stored);
    CHECK(s.count_events().value == 2);
    // Explicit dedupe key wins.
    StoreEvent e3 = ev(7);
    e3.dedupe_key = "custom";
    StoreEvent e4 = ev(8);
    e4.dedupe_key = "custom";
    CHECK(s.append_event(e3).status == AppendStatus::Stored);
    CHECK(s.append_event(e4).status == AppendStatus::Duplicate);
}

void test_restart_keeps_cursor_and_no_duplicates() {
    TempDir t;
    {
        StoreOpen o = EventStore::open(t.file());
        CHECK(o.ok);
        if (!o.ok) return;
        auto& s = open_ok(o);
        CHECK(s.record_lifecycle(kLifecycleStarted, "2026-10-30T00:00:00Z").status == AppendStatus::Stored);
        const std::vector<CheckStateRow> states = {{"firewall.public", "ENABLED", "2026-10-30T00:00:30Z"},
                                                   {"firewall.private", "DISABLED", "2026-10-30T00:00:30Z"}};
        const PollCommit p = s.record_poll({ev(1), ev(2)}, states, "2026-10-30T00:00:30Z", 1793363696);
        CHECK(p.ok);
        CHECK(p.stored == 2);
        CHECK(s.set_kv("custom", "value").ok);
    }
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    CHECK(s.last_observation_utc().value.value_or("") == "2026-10-30T00:00:30Z");
    CHECK(s.get_kv(kKvLastPollEpoch).value.value_or("") == "1793363696");
    CHECK(s.get_kv(kKvServiceStartedUtc).value.value_or("") == "2026-10-30T00:00:00Z");
    CHECK(s.get_kv("custom").value.value_or("") == "value");
    CHECK(!s.get_kv("missing").value.has_value());
    const auto states = s.load_check_states();
    CHECK(states.ok);
    CHECK(states.value.size() == 2);
    if (states.value.size() == 2) {
        CHECK(states.value[0].check_id == "firewall.private");
        CHECK(states.value[0].state == "DISABLED");
        CHECK(states.value[1].check_id == "firewall.public");
    }
    // The same poll replayed after "restart" stores nothing new.
    const PollCommit again = s.record_poll({ev(1), ev(2)}, states.value, "2026-10-30T00:00:30Z", 1793363696);
    CHECK(again.ok);
    CHECK(again.stored == 0);
    CHECK(again.duplicates == 2);
    CHECK(s.count_events().value == 3);  // started + 2 changes
    CHECK(s.stats().value.events_total == 3);
    // Same service_started second twice is one row.
    CHECK(s.record_lifecycle(kLifecycleStarted, "2026-10-30T00:00:00Z").status == AppendStatus::Duplicate);
    CHECK(s.record_lifecycle(kLifecycleStopped, "2026-10-30T00:09:00Z").status == AppendStatus::Stored);
    CHECK(!s.record_lifecycle("service_exploded", "x").ok());
}

void test_save_check_states_replaces() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    CHECK(s.save_check_states({{"a", "ENABLED", "t1"}, {"b", "DISABLED", "t1"}}).ok);
    CHECK(s.save_check_states({{"a", "DISABLED", "t2"}}).ok);
    const auto r = s.load_check_states();
    CHECK(r.value.size() == 1);
    if (!r.value.empty()) {
        CHECK(r.value[0].check_id == "a");
        CHECK(r.value[0].state == "DISABLED");
    }
    CHECK(s.count_events().value == 0);
}

void test_rotation_by_rows() {
    TempDir t;
    StoreLimits lim;
    lim.max_rows = 100;
    lim.prune_batch = 10;
    StoreOpen o = EventStore::open(t.file(), lim);
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    std::int64_t pruned = 0;
    for (int i = 1; i <= 350; ++i) {
        const AppendResult r = s.append_event(ev(i));
        CHECK(r.status == AppendStatus::Stored);
        pruned += r.pruned;
        const std::int64_t n = s.count_events().value;
        CHECK(n <= 100);
        if (n > 100) break;
    }
    CHECK(pruned == 350 - s.count_events().value);
    CHECK(s.count_events().value >= 90);
    const auto recent = s.recent_events(500);
    CHECK(recent.ok);
    CHECK(!recent.value.empty());
    if (!recent.value.empty()) {
        CHECK(recent.value.front().check_id == "firewall.public.350");  // newest survives
        CHECK(recent.value.back().id > 200);                             // oldest are gone
    }
    // lifetime counter is not reduced by rotation
    CHECK(s.stats().value.events_total == 350);
}

void test_rotation_by_bytes() {
    TempDir t;
    StoreLimits lim;
    lim.max_rows = 1000000;
    lim.max_bytes = 256 * 1024;
    lim.prune_batch = 5;
    StoreOpen o = EventStore::open(t.file(), lim);
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    bool over = false;
    std::int64_t pruned = 0;
    for (int i = 1; i <= 600; ++i) {
        const AppendResult r = s.append_event(ev(i, 250, 6));  // ~1.5 KB of evidence each
        CHECK(r.status == AppendStatus::Stored);
        pruned += r.pruned;
        std::error_code ec;
        if (fs::file_size(t.file(), ec) > static_cast<std::uintmax_t>(lim.max_bytes)) over = true;
    }
    CHECK(!over);
    CHECK(pruned > 0);
    CHECK(s.stats().value.db_bytes <= lim.max_bytes);
    const auto recent = s.recent_events(1);
    CHECK(recent.value.size() == 1);
    if (!recent.value.empty()) CHECK(recent.value[0].check_id == "firewall.public.600");
    CHECK(s.count_events().value < 600);
}

void test_oversize_single_poll_fails_clearly_and_store_survives() {
    TempDir t;
    StoreLimits lim;
    lim.max_bytes = 256 * 1024;
    StoreOpen o = EventStore::open(t.file(), lim);
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    CHECK(s.append_event(ev(1)).ok());
    std::vector<StoreEvent> many;
    for (int i = 0; i < 300; ++i) many.push_back(ev(1000 + i, 256, 16));  // ~ 5 KB each, 1.5 MB total
    const PollCommit p = s.record_poll(many, {}, "2026-10-30T00:00:30Z", 1);
    CHECK(!p.ok);
    CHECK(p.stored == 0 || !p.ok);
    CHECK(p.error.find("full") != std::string::npos);
    // The failed transaction left nothing half-written and the store still works.
    CHECK(s.append_event(ev(2)).status == AppendStatus::Stored);
    CHECK(s.recent_events(1).value.front().check_id == "firewall.public.2");
    std::error_code ec;
    CHECK(fs::file_size(t.file(), ec) <= static_cast<std::uintmax_t>(lim.max_bytes));
}

void test_reopen_with_smaller_cap_compacts() {
    TempDir t;
    {
        StoreLimits big;
        big.max_bytes = 4 * 1024 * 1024;
        StoreOpen o = EventStore::open(t.file(), big);
        CHECK(o.ok);
        if (!o.ok) return;
        for (int i = 1; i <= 500; ++i) CHECK(o.store->append_event(ev(i, 250, 6)).ok());
    }
    StoreLimits small;
    small.max_bytes = 256 * 1024;
    StoreOpen o = EventStore::open(t.file(), small);
    CHECK(o.ok);
    if (!o.ok) return;
    std::error_code ec;
    CHECK(fs::file_size(t.file(), ec) <= static_cast<std::uintmax_t>(small.max_bytes));
    CHECK(o.store->recent_events(1).value.front().check_id == "firewall.public.500");
}

void test_truncation() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    StoreEvent e = ev(1);
    e.kind = std::string(500, 'k');
    e.check_id = std::string(1000, 'c');
    e.source = std::string(1000, 's');
    e.error_code = std::string(1000, 'e');
    e.from_state = std::string(1000, 'f');
    e.observed_at_utc = std::string(1000, 't');
    e.evidence.clear();
    for (int i = 0; i < 40; ++i) e.evidence.emplace_back(std::string(300, 'K') + std::to_string(i), std::string(5000, 'V'));
    for (int i = 0; i < 40; ++i) e.evidence.emplace_back("p" + std::to_string(i), "w");
    CHECK(s.append_event(e).status == AppendStatus::Stored);
    const auto r = s.recent_events(1);
    CHECK(r.value.size() == 1);
    if (r.value.size() != 1) return;
    const StoredEvent& g = r.value[0];
    CHECK(g.kind.size() == kStoreMaxKind);
    CHECK(g.check_id.size() == kStoreMaxId);
    CHECK(g.source.size() == kStoreMaxId);
    CHECK(g.error_code.size() == kStoreMaxId);
    CHECK(g.from_state.size() == kStoreMaxState);
    CHECK(g.observed_at_utc.size() == kStoreMaxTimestamp);
    CHECK(g.evidence_valid);
    CHECK(g.evidence.size() == kStoreMaxEvidencePairs);  // 40 long keys collapse to 1, then 15 short ones fit
    if (!g.evidence.empty()) {
        CHECK(g.evidence[0].first.size() == kStoreMaxEvidenceKey);
        CHECK(g.evidence[0].second.size() == kStoreMaxEvidenceValue);
    }
    // UTF-8 is never split: "é" is 2 bytes, cut at an odd limit drops the whole character.
    CHECK(truncate_utf8("abcd", 10) == "abcd");
    CHECK(truncate_utf8("a\xC3\xA9", 2) == "a");
    CHECK(truncate_utf8("a\xC3\xA9", 3) == "a\xC3\xA9");
    CHECK(truncate_utf8("\xE2\x82\xAC", 2).empty());
    // kv values are truncated too
    CHECK(s.set_kv(std::string(500, 'k'), std::string(5000, 'v')).ok);
    CHECK(s.get_kv(std::string(500, 'k')).value.value_or("").size() == kStoreMaxKvValue);
}

void test_hostile_text_roundtrip_is_data_not_sql() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    StoreEvent e = ev(1);
    e.check_id = "x'); DROP TABLE events;--";
    e.evidence = {{"quote\"", "line1\nline2\\ \x01 \xC3\xA9"}, {"'; DELETE FROM kv;--", "v"}};
    CHECK(s.append_event(e).status == AppendStatus::Stored);
    CHECK(s.count_events().value == 1);
    const auto r = s.recent_events(5);
    CHECK(r.value.size() == 1);
    if (r.value.size() == 1) {
        CHECK(r.value[0].check_id == e.check_id);
        CHECK(r.value[0].evidence_valid);
        CHECK(r.value[0].evidence.size() == 2);
        if (r.value[0].evidence.size() == 2) CHECK(r.value[0].evidence[0].second == e.evidence[0].second);
    }
}

void test_recent_events_order_and_limit() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    auto& s = open_ok(o);
    for (int i = 1; i <= 30; ++i) CHECK(s.append_event(ev(i)).ok());
    const auto five = s.recent_events(5);
    CHECK(five.value.size() == 5);
    if (five.value.size() == 5) {
        CHECK(five.value[0].check_id == "firewall.public.30");
        CHECK(five.value[4].check_id == "firewall.public.26");
        CHECK(five.value[0].id > five.value[1].id);
    }
    CHECK(s.recent_events(0).value.size() == 1);    // clamped up
    CHECK(s.recent_events(-7).value.size() == 1);
    CHECK(s.recent_events(100000).value.size() == 30);  // clamped down to 500, only 30 exist
    for (int i = 31; i <= 700; ++i) CHECK(s.append_event(ev(i)).ok());
    CHECK(s.recent_events(100000).value.size() == static_cast<std::size_t>(kStoreMaxRecentEvents));
}

void test_closed_store_returns_errors() {
    TempDir t;
    StoreOpen o = EventStore::open(t.file());
    CHECK(o.ok);
    if (!o.ok) return;
    EventStore moved = std::move(*o.store);  // moved-from store must fail cleanly, not crash
    CHECK(!o.store->append_event(ev(1)).ok());
    CHECK(!o.store->recent_events(1).ok);
    CHECK(!o.store->count_events().ok);
    CHECK(!o.store->record_poll({}, {}, "x", 1).ok);
    CHECK(moved.append_event(ev(1)).ok());
}

}  // namespace

int main() {
    test_migration_and_basics();
    test_existing_empty_v0_database_is_migrated();
    test_foreign_database_with_same_table_is_refused();
    test_newer_schema_is_refused();
    test_garbage_file_is_clean_error();
    test_idempotent_append();
    test_restart_keeps_cursor_and_no_duplicates();
    test_save_check_states_replaces();
    test_rotation_by_rows();
    test_rotation_by_bytes();
    test_oversize_single_poll_fails_clearly_and_store_survives();
    test_reopen_with_smaller_cap_compacts();
    test_truncation();
    test_hostile_text_roundtrip_is_data_not_sql();
    test_recent_events_order_and_limit();
    test_closed_store_returns_errors();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
