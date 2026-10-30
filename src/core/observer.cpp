#include "observer.hpp"

#include <algorithm>
#include <exception>

namespace metasec {

namespace {

constexpr std::size_t kMaxPendingEvents = 1000;  // events waiting for a store that is failing

// A report that only carries the persisted confirmed states (used as the restart baseline).
StatusReport report_from_checkpoint(const std::vector<CheckStateRow>& rows) {
    StatusReport r;
    for (const auto& row : rows) {
        const auto st = state_from_string(row.state);
        if (!st) continue;  // unreadable value: treat the check as not persisted
        CheckResult c;
        c.check_id = row.check_id;
        c.state = *st;
        c.observed_at_utc = row.updated_utc;
        r.checks.push_back(std::move(c));
    }
    return r;
}

}  // namespace

const char* to_string(ObserverState s) {
    switch (s) {
        case ObserverState::Starting: return "starting";
        case ObserverState::Running: return "running";
        case ObserverState::Stopping: return "stopping";
        case ObserverState::Stopped: return "stopped";
    }
    return "stopped";
}

const char* to_string(ObserverStop s) {
    switch (s) {
        case ObserverStop::MaxPolls: return "max_polls";
        case ObserverStop::Interrupted: return "interrupted";
        case ObserverStop::Error: return "error";
    }
    return "error";
}

StoreEvent to_store_event(const WatchEvent& e) {
    StoreEvent s;
    s.kind = to_string(e.kind);
    s.observed_at_utc = e.observed_at_utc;
    s.first_observed_at_utc = e.first_observed_at_utc;
    s.check_id = e.check_id;
    if (e.from) s.from_state = to_string(*e.from);
    if (e.to) s.to_state = to_string(*e.to);
    s.confirmations = e.confirmations;
    s.source = e.source;
    s.error_code = e.error_code;
    s.evidence = e.evidence;
    return s;
}

Observer::Observer(EventStore* store, ObserverOptions opt, ObserverHooks hooks)
    : store_(store), opt_(std::move(opt)), hooks_(std::move(hooks)) {
    status_.version = opt_.version;
}

ObserverStatus Observer::status() const {
    std::lock_guard lock(mu_);
    return status_;
}

void Observer::update(const std::function<void(ObserverStatus&)>& f) {
    std::lock_guard lock(mu_);
    f(status_);
}

void Observer::note_store_error(const std::string& what) {
    update([&](ObserverStatus& s) {
        ++s.store_errors;
        s.last_error = what;
    });
}

ObserverResult Observer::run() {
    ObserverResult res;
    const std::string started = hooks_.now_utc();
    update([&](ObserverStatus& s) {
        s.state = ObserverState::Starting;
        s.started_utc = started;
    });

    std::vector<StoreEvent> pending;  // events whose commit failed, retried at the next poll
    long long recorded = 0;
    try {
        if (store_) {
            const AppendResult a = store_->record_lifecycle(kLifecycleStarted, started);
            if (!a.ok()) note_store_error("service_started not recorded: " + a.error);
            if (a.status == AppendStatus::Stored) ++recorded;
        }

        // Restart baseline: the confirmed states the previous run persisted.
        WatchTracker tracker(opt_.confirm_polls);
        bool restart_baseline = false;
        if (store_) {
            const auto cp = store_->load_check_states();
            if (!cp.ok) {
                note_store_error("checkpoint not loaded: " + cp.error);
            } else if (!cp.value.empty()) {
                const StatusReport base = report_from_checkpoint(cp.value);
                if (!base.checks.empty()) {
                    tracker.set_baseline(base);
                    restart_baseline = true;
                }
            }
        }
        std::string first_snapshot_utc;

        update([](ObserverStatus& s) { s.state = ObserverState::Running; });
        long long attempts = 0;
        for (;;) {
            if (hooks_.stop_requested()) {
                res.stop = ObserverStop::Interrupted;
                break;
            }
            ++attempts;
            bool have = false;
            StatusReport snap;
            try {
                snap = hooks_.snapshot();
                have = true;
            } catch (const std::exception& e) {
                update([&](ObserverStatus& s) {
                    ++s.snapshot_errors;
                    s.last_error = std::string("snapshot failed: ") + e.what();
                });
            }

            if (have) {
                if (first_snapshot_utc.empty()) first_snapshot_utc = snap.observed_at_utc;
                std::vector<WatchEvent> evs = tracker.observe(snap);
                for (auto& ev : evs) {
                    StoreEvent se = to_store_event(ev);
                    if (restart_baseline && ev.first_observed_at_utc == first_snapshot_utc)
                        se.evidence.insert(se.evidence.begin(), {"detected_after_restart", "true"});
                    pending.push_back(std::move(se));
                }
                if (pending.size() > kMaxPendingEvents) {
                    const std::size_t drop = pending.size() - kMaxPendingEvents;
                    pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(drop));
                    note_store_error(std::to_string(drop) + " events dropped: event store keeps failing");
                }

                std::vector<CheckStateRow> rows;
                for (const auto& [id, st] : tracker.confirmed_states())
                    rows.push_back({id, to_string(st), snap.observed_at_utc});

                if (store_) {
                    const long long epoch = hooks_.now_epoch ? hooks_.now_epoch() : -1;
                    const PollCommit pc = store_->record_poll(pending, rows, snap.observed_at_utc, epoch);
                    if (pc.ok) {
                        recorded += pc.stored;
                        pending.clear();
                    } else {
                        note_store_error(pc.error);
                    }
                } else {
                    pending.clear();
                    note_store_error(opt_.store_unavailable_reason.empty() ? "event store unavailable"
                                                                          : "event store unavailable: " + opt_.store_unavailable_reason);
                }

                long long total = 0;
                if (store_) {
                    const auto st = store_->stats();
                    if (st.ok) total = st.value.events_total;
                }
                const Overall overall = compute_overall(snap.checks);
                update([&](ObserverStatus& s) {
                    ++s.polls;
                    s.last_observation_utc = snap.observed_at_utc;
                    s.overall = overall;
                    if (store_) s.events_total = total;
                });
            }

            if (opt_.max_polls > 0 && attempts >= opt_.max_polls) {
                res.stop = ObserverStop::MaxPolls;
                break;
            }
            if (!hooks_.wait(opt_.interval_seconds)) {
                res.stop = ObserverStop::Interrupted;
                break;
            }
        }
    } catch (const std::exception& e) {
        res.stop = ObserverStop::Error;
        res.error = e.what();
    }

    update([](ObserverStatus& s) { s.state = ObserverState::Stopping; });
    try {
        if (store_) {
            const AppendResult a = store_->record_lifecycle(kLifecycleStopped, hooks_.now_utc());
            if (!a.ok()) note_store_error("service_stopped not recorded: " + a.error);
            if (a.status == AppendStatus::Stored) ++recorded;
        }
    } catch (const std::exception& e) {
        if (res.error.empty()) res.error = e.what();
    }
    long long total = 0;
    if (store_) {
        const auto st = store_->stats();
        if (st.ok) total = st.value.events_total;
    }
    update([&](ObserverStatus& s) {
        s.state = ObserverState::Stopped;
        if (store_) s.events_total = total;
    });

    const ObserverStatus fin = status();
    res.polls = fin.polls;
    res.store_errors = fin.store_errors;
    res.events_recorded = recorded;
    return res;
}

}  // namespace metasec
