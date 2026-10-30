// Deterministic unit tests for the audit rules (MVP-1). Every rule is exercised for PASS,
// FAIL, UNKNOWN and NOT_APPLICABLE where the rule can produce them, plus negative cases
// (UNKNOWN must never become PASS) and an exhaustive invariant sweep.
// `metasec_audit_tests --emit-json` prints a hostile audit report for the CMake JSON parser.
#include <cstdio>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "core/audit.hpp"
#include "core/cli.hpp"
#include "core/interpret.hpp"
#include "core/render.hpp"
#include "core/types.hpp"

using namespace metasec;

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

const char* const kNow = "2026-10-30T00:00:00Z";

CheckResult mk(const char* id, State s, const char* source = "fake") {
    CheckResult c;
    c.check_id = id;
    c.observed_at_utc = kNow;
    c.state = s;
    c.source = source;
    if (s == State::Unknown) c.error_code = "HRESULT:0x80004005";
    if (s == State::NotSupported) c.error_code = "HRESULT:0x8004100E";
    return c;
}

DefenderRaw normal_raw(long long age = 1) {
    DefenderRaw r;
    r.antivirus_enabled = true;
    r.realtime_enabled = true;
    r.running_mode = "Normal";
    r.signature_age_days = age;
    r.signature_version = "1.2.3.4";
    return r;
}

void set_check(AuditInput& in, const CheckResult& c) {
    for (auto& x : in.status.checks)
        if (x.check_id == c.check_id) {
            x = c;
            return;
        }
    in.status.checks.push_back(c);
}

void set_defender(AuditInput& in, const DefenderRaw& raw, State wsc = State::Good) {
    for (auto&& c : interpret_defender(raw, wsc, kNow)) set_check(in, c);
}

void set_defender_failure(AuditInput& in, State s, const char* code) {
    for (auto&& c : defender_failure(kNow, s, code)) set_check(in, c);
}

AvProductsObservation observed(std::vector<AvProduct> p) {
    AvProductsObservation o;
    o.obs = Obs::Observed;
    o.products = std::move(p);
    return o;
}

AvProductsObservation unobserved(Obs o, const char* code) {
    AvProductsObservation a;
    a.obs = o;
    a.error_code = code;
    return a;
}

constexpr long long kOn = 0x41000;       // 266240
constexpr long long kOff = 0x40000;      // 262144
constexpr long long kSnoozed = 0x42000;
constexpr long long kExpired = 0x43000;

// A healthy machine: all firewall profiles on, WSC good, Defender primary and on, fresh signatures.
AuditInput healthy() {
    AuditInput in;
    in.status.hostname = "host";
    in.status.observed_at_utc = kNow;
    in.status.platform = {"windows", "10.0.26200", "client"};
    set_check(in, mk(kIdFwDomain, State::Enabled));
    set_check(in, mk(kIdFwPrivate, State::Enabled));
    set_check(in, mk(kIdFwPublic, State::Enabled));
    set_check(in, mk(kIdWsc, State::Good));
    set_defender(in, normal_raw());
    in.av_products = observed({{"Windows Defender", kOn}});
    return in;
}

// Defender is not the primary engine (not running) and a third-party AV is registered.
AuditInput third_party(long long state = kOn) {
    AuditInput in = healthy();
    DefenderRaw raw = normal_raw();
    raw.running_mode = "Not running";
    set_defender(in, raw, State::Good);
    in.av_products = observed({{"Windows Defender", kOff}, {"Acme AV", state}});
    return in;
}

bool has_evidence(const Finding& f, const char* k, const char* v) {
    for (const auto& [ek, ev] : f.evidence)
        if (ek == k && ev == v) return true;
    return false;
}

// Every finding, whatever the result, carries what a reader needs to act on it.
void check_shape(const Finding& f) {
    CHECK(!f.rule_id.empty() && f.rule_id.rfind("META-", 0) == 0);
    CHECK(f.rule_version >= 1);
    CHECK(!f.title.empty());
    CHECK(!f.remediation.empty());
    CHECK(!f.evidence.empty());
    CHECK(!f.check_ids.empty());
}

// --- Firewall ------------------------------------------------------------------------------
void test_firewall() {
    const char* ids[] = {kIdFwDomain, kIdFwPrivate, kIdFwPublic};
    const char* rids[] = {"META-FW-001", "META-FW-002", "META-FW-003"};
    for (int i = 0; i < 3; ++i) {
        AuditInput in = healthy();
        Finding f = rule_firewall(in, ids[i]);
        CHECK(f.rule_id == rids[i]);
        CHECK(f.result == RuleResult::Pass);
        CHECK(f.severity == Severity::High);
        check_shape(f);

        set_check(in, mk(ids[i], State::Disabled));
        f = rule_firewall(in, ids[i]);
        CHECK(f.result == RuleResult::Fail);
        CHECK(has_evidence(f, "state", "DISABLED"));
        check_shape(f);
        CHECK(f.remediation.find("Firewall") != std::string::npos);

        for (State s : {State::Unknown, State::NotSupported}) {
            set_check(in, mk(ids[i], s));
            f = rule_firewall(in, ids[i]);
            CHECK(f.result == RuleResult::Unknown);
            CHECK(has_evidence(f, "error_code", s == State::Unknown ? "HRESULT:0x80004005" : "HRESULT:0x8004100E"));
            check_shape(f);
        }
        // the other two profiles are unaffected by this one
        AuditInput other = healthy();
        set_check(other, mk(ids[i], State::Disabled));
        for (int j = 0; j < 3; ++j)
            CHECK((rule_firewall(other, ids[j]).result == RuleResult::Fail) == (i == j));

        // check missing altogether
        AuditInput empty;
        f = rule_firewall(empty, ids[i]);
        CHECK(f.result == RuleResult::Unknown);
        check_shape(f);
    }
    // Negative: no state other than ENABLED passes, none other than DISABLED fails.
    const State all[] = {State::Enabled, State::Disabled, State::Good, State::Poor, State::Snooze,
                         State::NotMonitored, State::Passive, State::Unknown, State::NotSupported};
    for (State s : all) {
        AuditInput in = healthy();
        set_check(in, mk(kIdFwPublic, s));
        const RuleResult r = rule_firewall(in, kIdFwPublic).result;
        CHECK((r == RuleResult::Pass) == (s == State::Enabled));
        CHECK((r == RuleResult::Fail) == (s == State::Disabled));
    }
}

// --- Security Center health ------------------------------------------------------------------
void test_wsc() {
    AuditInput in = healthy();
    Finding f = rule_wsc_health(in);
    CHECK(f.rule_id == "META-AV-001" && f.result == RuleResult::Pass);
    check_shape(f);
    for (State s : {State::Poor, State::Snooze}) {
        set_check(in, mk(kIdWsc, s));
        f = rule_wsc_health(in);
        CHECK(f.result == RuleResult::Fail);
        CHECK(f.severity == Severity::High);
        check_shape(f);
    }
    // NOT_MONITORED: Windows does not track AV; neither pass nor proof of a problem.
    for (State s : {State::NotMonitored, State::Unknown, State::NotSupported}) {
        set_check(in, mk(kIdWsc, s));
        f = rule_wsc_health(in);
        CHECK(f.result == RuleResult::Unknown);
        check_shape(f);
    }
    const State all[] = {State::Enabled, State::Disabled, State::Good, State::Poor, State::Snooze,
                         State::NotMonitored, State::Passive, State::Unknown, State::NotSupported};
    for (State s : all) {
        set_check(in, mk(kIdWsc, s));
        CHECK((rule_wsc_health(in).result == RuleResult::Pass) == (s == State::Good));
    }
    AuditInput empty;
    CHECK(rule_wsc_health(empty).result == RuleResult::Unknown);
}

// --- productState decoding -------------------------------------------------------------------
void test_av_activity() {
    CHECK(av_activity(266240) == AvActivity::On);      // 0x41000, typical third-party AV, up to date
    CHECK(av_activity(266256) == AvActivity::On);      // 0x41010, on, signatures out of date
    CHECK(av_activity(397568) == AvActivity::On);      // 0x61100, Defender on
    CHECK(av_activity(393472) == AvActivity::Off);     // 0x60100, Defender off
    CHECK(av_activity(262144) == AvActivity::Off);
    CHECK(av_activity(kSnoozed) == AvActivity::Snoozed);
    CHECK(av_activity(kExpired) == AvActivity::Expired);
    CHECK(av_activity(0x44000) == AvActivity::Unrecognized);
    CHECK(av_activity(0xF000) == AvActivity::Unrecognized);
    CHECK(av_activity(-1) == AvActivity::Unrecognized);
    CHECK(av_activity(0x1000000) == AvActivity::Unrecognized);
    CHECK(std::string(to_string(AvActivity::On)) == "ON");
}

// --- Active antivirus engine -----------------------------------------------------------------
void test_active_av() {
    // A. Defender primary and on: PASS even if the product list is unavailable.
    {
        AuditInput in = healthy();
        Finding f = rule_active_av(in);
        CHECK(f.rule_id == "META-AV-002" && f.result == RuleResult::Pass);
        CHECK(has_evidence(f, "active_engine", "Microsoft Defender"));
        check_shape(f);
        in.av_products = unobserved(Obs::NotSupported, "HRESULT:0x8004100E");
        CHECK(rule_active_av(in).result == RuleResult::Pass);
    }
    // B. Defender passive + a third-party AV registered ON: PASS, product named in evidence.
    {
        AuditInput in = third_party();
        Finding f = rule_active_av(in);
        CHECK(f.result == RuleResult::Pass);
        CHECK(has_evidence(f, "active_engine", "Acme AV"));
        CHECK(has_evidence(f, "am_running_mode", "Not running"));
        check_shape(f);
    }
    // ... but not when that product is off, snoozed or expired (FAIL, with evidence).
    for (long long st : {kOff, kSnoozed, kExpired}) {
        AuditInput t = third_party(st);
        // Security Center GOOD while no product reads ON is contradictory: UNKNOWN, not FAIL.
        CHECK(rule_active_av(t).result == RuleResult::Unknown);
        set_check(t, mk(kIdWsc, State::Poor));
        Finding f = rule_active_av(t);
        CHECK(f.result == RuleResult::Fail);
        CHECK(f.severity == Severity::High);
        CHECK(has_evidence(f, "registered_products", "2"));
        check_shape(f);
    }
    // Passive Defender, nothing registered at all: contradictory (passive implies another engine),
    // so UNKNOWN even when Security Center agrees nothing is healthy.
    {
        AuditInput in = third_party();
        in.av_products = observed({});
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
        set_check(in, mk(kIdWsc, State::Poor));
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
    }
    // Defender not running, no AV registered, Security Center not healthy: FAIL.
    {
        AuditInput in = healthy();
        DefenderRaw raw = normal_raw();
        raw.running_mode = "Not running";
        set_defender(in, raw, State::NotMonitored);  // -> DISABLED
        set_check(in, mk(kIdWsc, State::NotMonitored));
        in.av_products = observed({});
        CHECK(rule_active_av(in).result == RuleResult::Fail);
        set_check(in, mk(kIdWsc, State::Good));  // contradiction -> UNKNOWN
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
    }
    // Defender is primary and off, but the list has an ON entry (Defender's own registration?):
    // never credited as another engine.
    {
        AuditInput in = healthy();
        DefenderRaw raw = normal_raw();
        raw.realtime_enabled = false;
        set_defender(in, raw);
        in.av_products = observed({{"Windows Defender", kOn}});
        Finding f = rule_active_av(in);
        CHECK(f.result == RuleResult::Unknown);
        in.av_products = observed({{"Windows Defender", kOn}, {"Acme AV", kOn}});
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
    }
    // Unnamed product that is ON still gets a readable engine label.
    {
        AuditInput in = third_party();
        in.av_products = observed({{"", kOn}});
        CHECK(has_evidence(rule_active_av(in), "active_engine", "(unnamed)"));
    }
    // Truncated list (error TRUNCATED, Obs::Unknown) cannot produce FAIL or PASS.
    {
        AuditInput in = third_party();
        in.av_products = unobserved(Obs::Unknown, "TRUNCATED");
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
    }
    // Passive Defender, list unavailable: UNKNOWN, never PASS (even though WSC says GOOD).
    for (Obs o : {Obs::Unknown, Obs::NotSupported}) {
        AuditInput in = third_party();
        in.av_products = unobserved(o, "HRESULT:0x80041003");
        Finding f = rule_active_av(in);
        CHECK(f.result == RuleResult::Unknown);
        CHECK(has_evidence(f, "registered_products_error", "HRESULT:0x80041003"));
        check_shape(f);
    }
    // Unrecognized productState: not ON, but not proof of absence either.
    {
        AuditInput in = third_party(0x44000);
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
        in.av_products = observed({{"Odd", 0x44000}, {"Real", kOn}});
        CHECK(rule_active_av(in).result == RuleResult::Pass);  // a recognized ON engine still counts
        in.av_products = observed({{"Odd", -1}});
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
    }
    // Defender unreadable: with no ON product we cannot say it is not protecting.
    {
        AuditInput in = healthy();
        set_defender_failure(in, State::Unknown, "TIMEOUT");
        in.av_products = observed({{"Windows Defender", kOff}});
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
        in.av_products = observed({{"Acme AV", kOn}});
        CHECK(rule_active_av(in).result == RuleResult::Pass);
        in.av_products = unobserved(Obs::Unknown, "TIMEOUT");
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
    }
    // No Defender provider at all (NotSupported) and nothing ON in the list: FAIL.
    {
        AuditInput in = healthy();
        set_defender_failure(in, State::NotSupported, "HRESULT:0x8004100E");
        set_check(in, mk(kIdWsc, State::NotMonitored));
        in.av_products = observed({});
        CHECK(rule_active_av(in).result == RuleResult::Fail);
    }
    // Defender is the primary engine and RT is off (flags false in Normal mode).
    {
        AuditInput in = healthy();
        DefenderRaw raw = normal_raw();
        raw.realtime_enabled = false;
        set_defender(in, raw);
        in.av_products = observed({{"Windows Defender", kOff}});
        CHECK(rule_active_av(in).result == RuleResult::Unknown);  // WSC GOOD contradicts
        set_check(in, mk(kIdWsc, State::Poor));
        CHECK(rule_active_av(in).result == RuleResult::Fail);
        set_check(in, mk(kIdWsc, State::Good));
        in.av_products = unobserved(Obs::NotSupported, "HRESULT:0x8004100E");  // Server SKU
        Finding f = rule_active_av(in);
        CHECK(f.result == RuleResult::Fail);
        CHECK(has_evidence(f, "am_running_mode", "Normal"));
        raw.antivirus_enabled = false;
        set_defender(in, raw);
        CHECK(rule_active_av(in).result == RuleResult::Fail);  // list unavailable, Defender primary and off
    }
    // Defender not running, Security Center not healthy, list unavailable: FAIL.
    {
        AuditInput in = healthy();
        DefenderRaw raw = normal_raw();
        raw.running_mode = "Not running";
        set_defender(in, raw, State::Poor);  // -> DISABLED
        set_check(in, mk(kIdWsc, State::Poor));
        in.av_products = unobserved(Obs::NotSupported, "HRESULT:0x8004100E");
        CHECK(rule_active_av(in).result == RuleResult::Fail);
        set_check(in, mk(kIdWsc, State::NotMonitored));  // cannot confirm: UNKNOWN
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
        set_check(in, mk(kIdWsc, State::Unknown));
        CHECK(rule_active_av(in).result == RuleResult::Unknown);
    }
    // Missing checks entirely, nothing observed: UNKNOWN.
    {
        AuditInput empty;
        Finding f = rule_active_av(empty);
        CHECK(f.result == RuleResult::Unknown);
        check_shape(f);
    }
}

// --- Defender real-time protection -----------------------------------------------------------
void test_defender_realtime() {
    AuditInput in = healthy();
    Finding f = rule_defender_realtime(in);
    CHECK(f.rule_id == "META-AV-003" && f.result == RuleResult::Pass);
    check_shape(f);

    DefenderRaw raw = normal_raw();
    raw.realtime_enabled = false;
    set_defender(in, raw);
    f = rule_defender_realtime(in);
    CHECK(f.result == RuleResult::Fail);
    CHECK(has_evidence(f, "realtime_protection", "DISABLED"));
    check_shape(f);

    for (const char* mode : {"Not running", "Passive", "SxS Passive Mode", "EDR Block Mode"}) {
        DefenderRaw p = normal_raw();
        p.running_mode = mode;
        set_defender(in, p, State::Good);
        f = rule_defender_realtime(in);
        CHECK(f.result == RuleResult::NotApplicable);
        check_shape(f);
    }
    // Unrecognized mode makes interpret_defender fail closed to UNKNOWN: UNKNOWN here too.
    {
        DefenderRaw p = normal_raw();
        p.running_mode = "normal";
        set_defender(in, p);
        CHECK(rule_defender_realtime(in).result == RuleResult::Unknown);
    }
    // Mode unavailable: flags are present but "primary" cannot be established.
    {
        DefenderRaw p = normal_raw();
        p.running_mode.reset();
        set_defender(in, p);
        f = rule_defender_realtime(in);
        CHECK(f.result == RuleResult::Unknown);
        check_shape(f);
    }
    set_defender_failure(in, State::Unknown, "TIMEOUT");
    f = rule_defender_realtime(in);
    CHECK(f.result == RuleResult::Unknown);
    check_shape(f);
    set_defender_failure(in, State::NotSupported, "HRESULT:0x8004100E");
    f = rule_defender_realtime(in);
    CHECK(f.result == RuleResult::NotApplicable);
    check_shape(f);
    // Mixed failure (one half unobserved) is never a pass.
    set_check(in, mk(kIdDefenderAv, State::Enabled));
    set_check(in, mk(kIdDefenderRt, State::Unknown));
    CHECK(rule_defender_realtime(in).result == RuleResult::Unknown);
    AuditInput empty;
    CHECK(rule_defender_realtime(empty).result == RuleResult::Unknown);
}

// --- Signature freshness ---------------------------------------------------------------------
void test_signature_age() {
    static_assert(kSignatureMaxAgeDays == 3, "threshold changes need a rule version bump and doc update");
    AuditInput in = healthy();
    Finding f = rule_signature_age(in);
    CHECK(f.rule_id == "META-AV-004" && f.result == RuleResult::Pass);
    CHECK(has_evidence(f, "signature_age_days", "1") && has_evidence(f, "threshold_days", "3"));
    CHECK(f.severity == Severity::Medium);
    check_shape(f);

    for (long long age : {0LL, 3LL}) {
        set_defender(in, normal_raw(age));
        CHECK(rule_signature_age(in).result == RuleResult::Pass);
    }
    for (long long age : {4LL, 30LL, 65534LL}) {
        set_defender(in, normal_raw(age));
        f = rule_signature_age(in);
        CHECK(f.result == RuleResult::Fail);
        check_shape(f);
    }
    // 65535 = "not available": interpret_defender drops the evidence, so the rule says UNKNOWN.
    set_defender(in, normal_raw(kSignatureAgeUnavailable));
    f = rule_signature_age(in);
    CHECK(f.result == RuleResult::Unknown);
    check_shape(f);
    {
        DefenderRaw raw = normal_raw();
        raw.signature_age_days.reset();
        set_defender(in, raw);
        CHECK(rule_signature_age(in).result == RuleResult::Unknown);
    }
    // Malformed / negative evidence is never trusted.
    for (const char* bad : {"-1", "abc", "", "3x", " 3", "99999999999999999999"}) {
        AuditInput bad_in = healthy();
        for (auto& c : bad_in.status.checks)
            if (c.check_id == kIdDefenderAv)
                for (auto& [k, v] : c.evidence)
                    if (k == "signature_age_days") v = bad;
        CHECK(rule_signature_age(bad_in).result == RuleResult::Unknown);
    }
    // Not the primary engine: its signature age is not a reliable signal for the active AV.
    for (const char* mode : {"Not running", "Passive", "SxS Passive Mode"}) {
        DefenderRaw raw = normal_raw(400);
        raw.running_mode = mode;
        set_defender(in, raw, State::Good);
        f = rule_signature_age(in);
        CHECK(f.result == RuleResult::NotApplicable);
        check_shape(f);
    }
    {
        DefenderRaw raw = normal_raw();
        raw.running_mode.reset();
        set_defender(in, raw);
        CHECK(rule_signature_age(in).result == RuleResult::Unknown);
    }
    set_defender_failure(in, State::Unknown, "TIMEOUT");
    CHECK(rule_signature_age(in).result == RuleResult::Unknown);
    set_defender_failure(in, State::NotSupported, "HRESULT:0x8004100E");
    f = rule_signature_age(in);
    CHECK(f.result == RuleResult::NotApplicable);
    check_shape(f);
    AuditInput empty;
    CHECK(rule_signature_age(empty).result == RuleResult::Unknown);
}

// --- Whole audit: ordering, summary, overall, exit code ----------------------------------------
void test_run_audit() {
    AuditReport r = run_audit(healthy());
    CHECK(r.findings.size() == 7);
    std::set<std::string> ids;
    for (const auto& f : r.findings) ids.insert(f.rule_id);
    CHECK(ids.size() == r.findings.size());
    CHECK(r.findings[0].rule_id == "META-FW-001" && r.findings[6].rule_id == "META-AV-004");
    CHECK(r.hostname == "host");
    for (const auto& f : r.findings) CHECK(!f.sources.empty());  // provenance names a data source
    AuditSummary s = summarize(r);
    CHECK(s.pass == 7 && s.fail == 0 && s.unknown == 0 && s.not_applicable == 0);
    CHECK(audit_overall(r) == AuditOverall::NoFindings);
    CHECK(audit_exit_code(audit_overall(r)) == kExitOk);

    // This lab machine's shape: Defender passive, third-party AV on.
    r = run_audit(third_party());
    s = summarize(r);
    CHECK(s.pass == 5 && s.not_applicable == 2 && s.fail == 0 && s.unknown == 0);
    CHECK(audit_exit_code(audit_overall(r)) == kExitOk);

    // A confirmed FAIL exits 1, even when another rule is UNKNOWN (1 outranks 3).
    AuditInput in = healthy();
    set_check(in, mk(kIdFwPublic, State::Disabled));
    set_check(in, mk(kIdWsc, State::Unknown));
    r = run_audit(in);
    s = summarize(r);
    CHECK(s.fail == 1 && s.unknown == 1);
    CHECK(audit_overall(r) == AuditOverall::Findings);
    CHECK(audit_exit_code(audit_overall(r)) == kExitViolation);

    // Only UNKNOWN: exit 3, never 0.
    in = healthy();
    set_check(in, mk(kIdFwDomain, State::Unknown));
    r = run_audit(in);
    CHECK(audit_overall(r) == AuditOverall::Incomplete);
    CHECK(audit_exit_code(audit_overall(r)) == kExitIncomplete);

    // Nothing observed at all: every status-based rule UNKNOWN, exit 3.
    AuditInput none;
    none.av_products = unobserved(Obs::Unknown, "TIMEOUT");
    r = run_audit(none);
    CHECK(summarize(r).pass == 0);
    CHECK(audit_exit_code(audit_overall(r)) == kExitIncomplete);
    CHECK(audit_overall(AuditReport{}) == AuditOverall::Incomplete);
}

// --- Lab profiles (fixtures; no OS setting is changed) -----------------------------------------
// "Secure" and "insecure" profiles stand in for controlled lab machines: they are loaded into
// the core as observations, so they prove the rule logic, not behaviour on a weakened real OS.
void test_lab_profiles() {
    // Secure profile: expect no FAIL / UNKNOWN.
    AuditReport secure = run_audit(healthy());
    CHECK(summarize(secure).fail == 0 && summarize(secure).unknown == 0);
    CHECK(audit_exit_code(audit_overall(secure)) == 0);

    // Insecure profile: public firewall off, Defender RT off in Normal mode, signatures 30 days old.
    AuditInput bad = healthy();
    set_check(bad, mk(kIdFwPublic, State::Disabled));
    set_check(bad, mk(kIdWsc, State::Poor));
    DefenderRaw raw = normal_raw(30);
    raw.realtime_enabled = false;
    set_defender(bad, raw, State::Poor);
    bad.av_products = observed({{"Windows Defender", kOff}});
    const AuditReport r = run_audit(bad);
    std::set<std::string> failed;
    for (const auto& f : r.findings)
        if (f.result == RuleResult::Fail) failed.insert(f.rule_id);
    const std::set<std::string> expected = {"META-FW-003", "META-AV-001", "META-AV-002", "META-AV-003", "META-AV-004"};
    CHECK(failed == expected);
    CHECK(audit_exit_code(audit_overall(r)) == 1);
    for (const auto& f : r.findings)
        if (f.result == RuleResult::Fail) {
            CHECK(!f.remediation.empty() && !f.evidence.empty());
        }
}

// --- Invariant sweep over many input combinations ------------------------------------------------
void test_invariants() {
    const State fw_states[] = {State::Enabled, State::Disabled, State::Unknown, State::NotSupported};
    const State wsc_states[] = {State::Good, State::Poor, State::Snooze, State::NotMonitored, State::Unknown,
                                State::NotSupported};
    enum { kNormalOn, kNormalRtOff, kNormalOff, kNotRunning, kPassive, kFailUnknown, kFailNs, kBadMode, kOldSigs, kCount };
    const AvProductsObservation lists[] = {
        observed({}),
        observed({{"A", kOn}}),
        observed({{"A", kOff}, {"B", kSnoozed}}),
        observed({{"A", 0x44000}}),
        unobserved(Obs::Unknown, "TIMEOUT"),
        unobserved(Obs::NotSupported, "HRESULT:0x8004100E"),
    };
    long long combos = 0;
    for (State f1 : fw_states)
        for (State f2 : fw_states)
            for (State w : wsc_states)
                for (int d = 0; d < kCount; ++d)
                    for (const auto& list : lists) {
                        AuditInput in;
                        in.status.hostname = "h";
                        set_check(in, mk(kIdFwDomain, f1));
                        set_check(in, mk(kIdFwPrivate, f2));
                        set_check(in, mk(kIdFwPublic, f1));
                        set_check(in, mk(kIdWsc, w));
                        DefenderRaw raw = normal_raw();
                        switch (d) {
                            case kNormalRtOff: raw.realtime_enabled = false; break;
                            case kNormalOff: raw.realtime_enabled = false; raw.antivirus_enabled = false; break;
                            case kNotRunning: raw.running_mode = "Not running"; break;
                            case kPassive: raw.running_mode = "Passive"; break;
                            case kBadMode: raw.running_mode = "weird"; break;
                            case kOldSigs: raw.signature_age_days = 90; break;
                            default: break;
                        }
                        if (d == kFailUnknown) set_defender_failure(in, State::Unknown, "TIMEOUT");
                        else if (d == kFailNs) set_defender_failure(in, State::NotSupported, "HRESULT:0x8004100E");
                        else set_defender(in, raw, w);
                        in.av_products = list;

                        const AuditReport r = run_audit(in);
                        ++combos;
                        CHECK(r.findings.size() == 7);
                        std::set<std::string> ids;
                        for (const auto& f : r.findings) {
                            ids.insert(f.rule_id);
                            CHECK(!f.remediation.empty());
                        }
                        CHECK(ids.size() == 7);

                        // UNKNOWN is never PASS: rules whose single input was not observed.
                        const bool fw_obs[] = {f1 == State::Enabled || f1 == State::Disabled,
                                               f2 == State::Enabled || f2 == State::Disabled,
                                               f1 == State::Enabled || f1 == State::Disabled};
                        for (int i = 0; i < 3; ++i) {
                            const RuleResult res = r.findings[static_cast<std::size_t>(i)].result;
                            if (!fw_obs[i]) CHECK(res == RuleResult::Unknown);
                        }
                        if (w == State::NotMonitored || w == State::Unknown || w == State::NotSupported)
                            CHECK(r.findings[3].result == RuleResult::Unknown);
                        // AV-002 PASS requires positive evidence of an engine.
                        if (r.findings[4].result == RuleResult::Pass) {
                            const bool def_on = has_evidence(r.findings[4], "active_engine", "Microsoft Defender");
                            bool list_on = false;
                            if (list.obs == Obs::Observed)
                                for (const auto& p : list.products) list_on = list_on || av_activity(p.product_state) == AvActivity::On;
                            CHECK(def_on || list_on);
                        }
                        // Exit-code contract.
                        const AuditSummary s = summarize(r);
                        CHECK(s.pass + s.fail + s.unknown + s.not_applicable == 7);
                        const int rc = audit_exit_code(audit_overall(r));
                        CHECK((rc == 1) == (s.fail > 0));
                        CHECK((rc == 3) == (s.fail == 0 && s.unknown > 0));
                        CHECK((rc == 0) == (s.fail == 0 && s.unknown == 0));
                    }
    CHECK(combos == 4 * 4 * 6 * kCount * 6);
}

// --- Rendering -----------------------------------------------------------------------------------
void test_render() {
    const AuditReport r = run_audit(third_party());
    const std::string j = render_audit_json(r, "9.9.9");
    CHECK(j.back() == '\n' && j.find('\n') == j.size() - 1);  // exactly one line
    CHECK(j.find("\"schema_version\":1") != std::string::npos);
    CHECK(j.find("\"command\":\"audit\"") != std::string::npos);
    CHECK(j.find("\"rule_id\":\"META-AV-002\"") != std::string::npos);
    CHECK(j.find("\"rule_version\":1") != std::string::npos);
    CHECK(j.find("\"result\":\"NOT_APPLICABLE\"") != std::string::npos);
    CHECK(j.find("\"provenance\":{\"check_ids\":") != std::string::npos);
    CHECK(j.find("\"summary\":{\"pass\":5,\"fail\":0,\"unknown\":0,\"not_applicable\":2}") != std::string::npos);
    CHECK(j.find("\"overall\":\"NO_FINDINGS\"") != std::string::npos);
    CHECK(j.find("\"version\":\"9.9.9\"") != std::string::npos);
    const std::string t = render_audit_text(r, "9.9.9");
    CHECK(t.find("[PASS] META-FW-001") != std::string::npos);
    CHECK(t.find("[NOT_APPLICABLE] META-AV-004") != std::string::npos);
    CHECK(t.find("Overall: NO_FINDINGS") != std::string::npos);
    CHECK(t.find("fix:") == std::string::npos);  // remediation is shown only for FAIL / UNKNOWN

    {
        AuditInput hostile = third_party();
        hostile.av_products = observed({{std::string("Evil") + "\x1b[31m" + "\n" + "red", kOn}});
        const std::string th = render_audit_text(run_audit(hostile), "1");
        CHECK(th.find('\x1b') == std::string::npos);
        CHECK(th.find("red") != std::string::npos);
    }
    AuditInput in = healthy();
    set_check(in, mk(kIdFwPublic, State::Disabled));
    const std::string tf = render_audit_text(run_audit(in), "1");
    CHECK(tf.find("[FAIL] META-FW-003") != std::string::npos);
    CHECK(tf.find("fix:") != std::string::npos);
    CHECK(tf.find("Overall: FINDINGS") != std::string::npos);
}

void test_args() {
    auto parse = [](std::vector<std::string_view> a) { return parse_args(a); };
    CHECK(parse({"audit"}).command == Command::Audit);
    CHECK(!parse({"audit"}).json);
    CHECK(parse({"audit", "--json"}).command == Command::Audit);
    CHECK(parse({"audit", "--json"}).json);
    CHECK(parse({"audit", "--bogus"}).command == Command::Invalid);
    CHECK(parse({"audit", "--json", "--json"}).command == Command::Invalid);
    CHECK(parse({"audit", "--json", "x"}).command == Command::Invalid);
    CHECK(parse({"AUDIT"}).command == Command::Invalid);
    CHECK(parse({"status", "--json"}).command == Command::Status);  // status unchanged
    CHECK(usage_text("1").find("meta-sec audit") != std::string::npos);
}

int emit_hostile_json() {
    AuditInput in = healthy();
    in.status.hostname = std::string("a\"b\\c\nd\x01") + "\xFF" + "end";
    set_check(in, mk(kIdFwPublic, State::Disabled, "src\\\"x"));
    in.av_products = observed({{"Evil \"AV\"\n\\", kOn}});
    set_check(in, mk(kIdDefenderAv, State::Disabled));
    set_check(in, mk(kIdDefenderRt, State::Disabled));
    const std::string j = render_audit_json(run_audit(in), "1");
    std::fwrite(j.data(), 1, j.size(), stdout);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--emit-json") return emit_hostile_json();
    test_firewall();
    test_wsc();
    test_av_activity();
    test_active_av();
    test_defender_realtime();
    test_signature_age();
    test_run_audit();
    test_lab_profiles();
    test_invariants();
    test_render();
    test_args();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
