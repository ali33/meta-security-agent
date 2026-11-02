// Deterministic unit tests for the local baseline policy (MVP-5): strict parsing (including hostile
// files), pure evaluation against fake audit reports, exit-code precedence, rendering.
// `metasec_policy_tests --emit-json` prints a hostile drift report for the CMake JSON parser.
#include <cstdio>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "core/audit.hpp"
#include "core/cli.hpp"
#include "core/interpret.hpp"
#include "core/json.hpp"
#include "core/policy.hpp"
#include "core/render.hpp"
#include "core/sha256.hpp"
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

// ---- fake audit reports -------------------------------------------------------------------------

Finding finding(const char* id, RuleResult r, std::vector<std::pair<std::string, std::string>> ev = {}) {
    Finding f;
    f.rule_id = id;
    f.rule_version = 1;
    f.title = std::string("title of ") + id;
    f.result = r;
    f.severity = Severity::High;
    f.remediation = "fix it by hand";
    f.evidence = std::move(ev);
    f.check_ids = {"c1"};
    f.sources = {"fake source"};
    return f;
}

AuditReport audit_all(RuleResult r) {
    AuditReport a;
    a.hostname = "host";
    a.observed_at_utc = "2026-11-02T00:00:00Z";
    a.platform = {"windows", "10.0.26200", "client"};
    for (const auto& id : known_policy_rule_ids()) {
        std::vector<std::pair<std::string, std::string>> ev;
        if (id == kSignatureAgeRule && (r == RuleResult::Pass || r == RuleResult::Fail)) ev.emplace_back("signature_age_days", "1");
        a.findings.push_back(finding(id.c_str(), r, ev));
    }
    return a;
}

Policy policy_of(std::vector<PolicyRule> rules) {
    Policy p;
    p.policy_id = "t";
    p.policy_version = 1;
    p.source = "file";
    p.rules = std::move(rules);
    return p;
}

const PolicyRuleResult* by_id(const PolicyReport& r, const char* id) {
    for (const auto& x : r.rules)
        if (x.rule_id == id) return &x;
    return nullptr;
}

std::string doc(const std::string& rules, const std::string& extra = "") {
    return "{\"schema_version\":1,\"policy_id\":\"p\",\"policy_version\":1," + extra + "\"rules\":" + rules + "}";
}

const std::string kOneRule = "[{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\"}]";

// ---- parsing ------------------------------------------------------------------------------------

void test_default_policy() {
    const PolicyParseResult r = parse_policy(default_policy_json());
    CHECK(r.ok);
    CHECK(r.policy.policy_id == "meta-default-baseline");
    CHECK(r.policy.policy_version == 1);
    CHECK(r.policy.rules.size() == known_policy_rule_ids().size());
    const Policy d = default_policy();
    CHECK(d.source == "built-in");
    CHECK(d.rules.size() == known_policy_rule_ids().size());
    // The built-in baseline must name exactly the rules the audit produces, in the audit's order, and its
    // signature limit must equal the audit's own constant (so the default is not silently looser or stricter).
    const AuditReport empty = run_audit(AuditInput{});
    CHECK(empty.findings.size() == d.rules.size());
    for (std::size_t i = 0; i < d.rules.size() && i < empty.findings.size(); ++i) CHECK(d.rules[i].rule_id == empty.findings[i].rule_id);
    for (std::size_t i = 0; i < d.rules.size(); ++i) {
        if (d.rules[i].rule_id == kSignatureAgeRule) {
            CHECK(d.rules[i].max_signature_age_days.has_value());
            CHECK(d.rules[i].max_signature_age_days && *d.rules[i].max_signature_age_days == kSignatureMaxAgeDays);
        } else {
            CHECK(!d.rules[i].max_signature_age_days);
        }
    }
    // known ids == audit ids
    std::set<std::string> a(known_policy_rule_ids().begin(), known_policy_rule_ids().end());
    std::set<std::string> b;
    for (const auto& f : empty.findings) b.insert(f.rule_id);
    CHECK(a == b);
}

void test_parse_valid() {
    CHECK(parse_policy(doc(kOneRule)).ok);
    // BOM, whitespace, key order
    CHECK(parse_policy("\xEF\xBB\xBF " + doc(kOneRule) + "\n").ok);
    CHECK(parse_policy("{\"rules\":" + kOneRule + ",\"policy_version\":7,\"policy_id\":\"A.b_c-1\",\"schema_version\":1}").ok);
    const auto r = parse_policy(doc("[{\"rule_id\":\"META-AV-004\",\"expect\":\"PASS\",\"max_signature_age_days\":2}]"));
    CHECK(r.ok && r.policy.rules.size() == 1 && r.policy.rules[0].max_signature_age_days == 2);
    CHECK(r.ok && r.policy.source == "file");
    // limits are inclusive
    CHECK(parse_policy(doc("[{\"rule_id\":\"META-AV-004\",\"expect\":\"PASS\",\"max_signature_age_days\":1}]")).ok);
    CHECK(parse_policy(doc("[{\"rule_id\":\"META-AV-004\",\"expect\":\"PASS\",\"max_signature_age_days\":3}]")).ok);  // = audit limit
    // A policy can only TIGHTEN the audit limit: anything above kSignatureMaxAgeDays (3) is an error.
    for (const char* loose : {"4", "5", "7", "30", "365", "366"}) {
        const auto lr = parse_policy(doc(std::string("[{\"rule_id\":\"META-AV-004\",\"expect\":\"PASS\",\"max_signature_age_days\":") + loose + "}]"));
        CHECK(!lr.ok && lr.error.find("only tighten") != std::string::npos && lr.error.find("1 to 3") != std::string::npos);
    }
    CHECK(parse_policy("{\"schema_version\":1,\"policy_id\":\"" + std::string(64, 'a') + "\",\"policy_version\":1000000,\"rules\":" + kOneRule + "}").ok);
    // all seven rules, at the maximum allowed size of a whitespace-padded file
    std::string padded = doc(kOneRule);
    padded.append(kMaxPolicyBytes - padded.size(), ' ');
    CHECK(padded.size() == kMaxPolicyBytes);
    CHECK(parse_policy(padded).ok);
}

void expect_reject(const std::string& text, const char* what) {
    const PolicyParseResult r = parse_policy(text);
    ++g_checks;
    if (r.ok || r.error.empty()) {
        ++g_failed;
        std::fprintf(stderr, "FAIL: accepted or empty error: %s\n", what);
    }
    // The error never echoes arbitrary input: bounded length, no control characters.
    CHECK(r.error.size() <= 400);
    for (char c : r.error) CHECK(static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) != 0x7F);
    // A rejected document yields no rules (never a half-parsed policy to evaluate).
    CHECK(r.policy.rules.empty() || !r.ok);
}

void test_parse_hostile() {
    expect_reject("", "empty");
    expect_reject("   ", "blank");
    expect_reject("\xEF\xBB\xBF", "bom only");
    expect_reject("null", "null");
    expect_reject("[]", "array root");
    expect_reject("\"x\"", "string root");
    expect_reject("42", "number root");
    expect_reject("{", "truncated");
    expect_reject(doc(kOneRule) + "x", "trailing garbage");
    expect_reject(doc(kOneRule) + doc(kOneRule), "two documents");
    expect_reject("// c\n" + doc(kOneRule), "comment");
    expect_reject("{\"schema_version\":1,\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + ",}", "trailing comma");
    expect_reject("{'schema_version':1}", "single quotes");
    expect_reject(std::string("\xFF\xFE{\0}", 5), "utf-16 bom / nul");
    expect_reject(std::string("{\"schema_version\":1,\"policy_id\":\"p\xC3\",\"policy_version\":1,\"rules\":") + kOneRule + "}", "invalid utf-8");
    expect_reject("{\"schema_version\":1,\"policy_id\":\"p\n\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "raw newline in string");
    // missing required keys
    expect_reject("{}", "empty object");
    expect_reject("{\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "no schema_version");
    expect_reject("{\"schema_version\":1,\"policy_version\":1,\"rules\":" + kOneRule + "}", "no policy_id");
    expect_reject("{\"schema_version\":1,\"policy_id\":\"p\",\"rules\":" + kOneRule + "}", "no policy_version");
    expect_reject("{\"schema_version\":1,\"policy_id\":\"p\",\"policy_version\":1}", "no rules");
    // schema version
    expect_reject("{\"schema_version\":2,\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "future schema");
    expect_reject("{\"schema_version\":0,\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "schema 0");
    expect_reject("{\"schema_version\":\"1\",\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "schema as string");
    expect_reject("{\"schema_version\":1.0,\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "schema as float");
    expect_reject("{\"schema_version\":1e0,\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "schema exponent");
    expect_reject("{\"schema_version\":true,\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "schema bool");
    // policy id / version
    for (const char* bad : {"\"\"", "\"has space\"", "\"a/b\"", "\"a\\\\b\"", "\"..\\\\x\"", "\"a:b\"", "\"\\u0000\"", "\"é\"", "1", "null", "[]"})
        expect_reject(std::string("{\"schema_version\":1,\"policy_id\":") + bad + ",\"policy_version\":1,\"rules\":" + kOneRule + "}",
                      "bad policy_id");
    expect_reject("{\"schema_version\":1,\"policy_id\":\"" + std::string(65, 'a') + "\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "long id");
    for (const char* bad : {"0", "-1", "1000001", "1.5", "\"1\"", "99999999999999999999", "null"})
        expect_reject(std::string("{\"schema_version\":1,\"policy_id\":\"p\",\"policy_version\":") + bad + ",\"rules\":" + kOneRule + "}",
                      "bad policy_version");
    // unknown keys (top level and in a rule)
    expect_reject(doc(kOneRule, "\"extra\":1,"), "unknown top-level key");
    expect_reject(doc(kOneRule, "\"description\":\"x\","), "unknown top-level key (description)");
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\",\"severity\":\"LOW\"}]"), "unknown rule key");
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\",\"remediate\":true}]"), "remediation key (MVP-6 is not here)");
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\",\"RULE_ID\":\"x\"}]"), "case-variant key");
    // duplicate keys (strict JSON parser)
    expect_reject("{\"schema_version\":1,\"schema_version\":1,\"policy_id\":\"p\",\"policy_version\":1,\"rules\":" + kOneRule + "}", "duplicate top key");
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\",\"rule_id\":\"META-FW-002\",\"expect\":\"PASS\"}]"), "duplicate rule key");
    // rules shape
    expect_reject(doc("[]"), "empty rules");
    expect_reject(doc("{}"), "rules as object");
    expect_reject(doc("\"META-FW-001\""), "rules as string");
    expect_reject(doc("null"), "rules null");
    expect_reject(doc("[\"META-FW-001\"]"), "rule as string");
    expect_reject(doc("[null]"), "rule null");
    expect_reject(doc("[[]]"), "rule array");
    expect_reject(doc("[{}]"), "rule without keys");
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\"}]"), "no expect");
    expect_reject(doc("[{\"expect\":\"PASS\"}]"), "no rule_id");
    // unknown / malformed rule ids
    for (const char* bad : {"META-FW-004", "META-XX-001", "meta-fw-001", "META-FW-001 ", " META-FW-001", "META-FW-0011", "META-FW-01",
                            "", "*", "META-*", "META-FW-001\\u0000", "../META-FW-001", "META-FW-001\\nMETA-FW-002", "META-AV-005", "all"})
        expect_reject(doc(std::string("[{\"rule_id\":\"") + bad + "\",\"expect\":\"PASS\"}]"), bad);
    expect_reject(doc("[{\"rule_id\":1,\"expect\":\"PASS\"}]"), "numeric rule id");
    expect_reject(doc("[{\"rule_id\":null,\"expect\":\"PASS\"}]"), "null rule id");
    // expectations other than PASS
    for (const char* bad : {"\"FAIL\"", "\"pass\"", "\"UNKNOWN\"", "\"NOT_APPLICABLE\"", "\"PASS \"", "true", "1", "null", "\"\""})
        expect_reject(doc(std::string("[{\"rule_id\":\"META-FW-001\",\"expect\":") + bad + "}]"), bad);
    // duplicate rule id
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\"},{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\"}]"), "duplicate rule");
    // parameter misuse
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\",\"max_signature_age_days\":3}]"), "param on the wrong rule");
    for (const char* bad : {"0", "-1", "4", "365", "366", "3.5", "3e0", "\"3\"", "null", "true", "99999999999999999999", "[]"})
        expect_reject(doc(std::string("[{\"rule_id\":\"META-AV-004\",\"expect\":\"PASS\",\"max_signature_age_days\":") + bad + "}]"), bad);
    // too many rules (more than the 32 allowed, even though ids repeat -> rejected either way)
    {
        std::string many = "[";
        for (int i = 0; i < 33; ++i) many += std::string(i ? "," : "") + "{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\"}";
        many += "]";
        const auto r = parse_policy(doc(many));
        CHECK(!r.ok && r.error.find("more than") != std::string::npos);
    }
    // nesting bomb and size bomb
    expect_reject(std::string(5000, '[') + std::string(5000, ']'), "deep nesting");
    expect_reject(doc("[{\"rule_id\":\"META-FW-001\",\"expect\":\"PASS\",\"x\":" + std::string(20, '[') + std::string(20, ']') + "}]"), "nested junk");
    {
        std::string big = doc(kOneRule);
        big.append(kMaxPolicyBytes - big.size() + 1, ' ');
        const auto r = parse_policy(big);
        CHECK(!r.ok && r.error.find("larger than") != std::string::npos);
    }
    expect_reject(std::string(10 * 1024 * 1024, 'x'), "10 MiB of junk");
    // a hostile key name is sanitized in the error
    {
        const auto r = parse_policy(doc(kOneRule, "\"\x1b[31mevil\":1,"));
        CHECK(!r.ok && r.error.find('\x1b') == std::string::npos);
        const auto r2 = parse_policy(doc("[{\"rule_id\":\"" + std::string(500, 'A') + "\",\"expect\":\"PASS\"}]"));
        CHECK(!r2.ok && r2.error.size() < 200);
    }
}

// ---- evaluation ---------------------------------------------------------------------------------

void test_verdict_table() {
    struct Row { RuleResult audit; PolicyVerdict want; };
    const Row rows[] = {{RuleResult::Pass, PolicyVerdict::Compliant},
                        {RuleResult::Fail, PolicyVerdict::Drift},
                        {RuleResult::Unknown, PolicyVerdict::Incomplete},
                        {RuleResult::NotApplicable, PolicyVerdict::NotApplicable}};
    for (const Row& row : rows) {
        const PolicyReport r = evaluate_policy(default_policy(), audit_all(row.audit));
        CHECK(r.rules.size() == known_policy_rule_ids().size());
        for (const auto& x : r.rules) {
            if (x.rule_id == kSignatureAgeRule) continue;  // parameterised, covered below
            CHECK(x.verdict == row.want);
            CHECK(x.observed == row.audit);
            CHECK(!x.detail.empty());
            CHECK(x.rule_version == 1 && !x.title.empty() && !x.remediation.empty());
            CHECK(!x.check_ids.empty() && !x.sources.empty());
        }
    }
    // Invariant sweep: with one rule in the policy, COMPLIANT appears iff the audit said PASS.
    for (const auto& id : known_policy_rule_ids()) {
        if (id == kSignatureAgeRule) continue;
        for (RuleResult rr : {RuleResult::Pass, RuleResult::Fail, RuleResult::Unknown, RuleResult::NotApplicable}) {
            AuditReport a = audit_all(RuleResult::Fail);
            for (auto& f : a.findings)
                if (f.rule_id == id) f.result = rr;
            const PolicyReport r = evaluate_policy(policy_of({{id, std::nullopt}}), a);
            CHECK(r.rules.size() == 1);
            CHECK((r.rules[0].verdict == PolicyVerdict::Compliant) == (rr == RuleResult::Pass));
            CHECK((r.rules[0].verdict == PolicyVerdict::Drift) == (rr == RuleResult::Fail));
            CHECK((r.rules[0].verdict == PolicyVerdict::Incomplete) == (rr == RuleResult::Unknown));
        }
    }
}

void test_missing_rule_is_incomplete() {
    AuditReport a = audit_all(RuleResult::Pass);
    a.findings.erase(a.findings.begin());  // META-FW-001 disappears from the audit
    const PolicyReport r = evaluate_policy(policy_of({{"META-FW-001", std::nullopt}}), a);
    CHECK(r.rules.size() == 1 && r.rules[0].verdict == PolicyVerdict::Incomplete);
    CHECK(r.rules[0].observed == RuleResult::Unknown);
    CHECK(!r.rules[0].title.empty() && !r.rules[0].remediation.empty() && !r.rules[0].check_ids.empty());
    CHECK(render_policy_text(r, "1").find("fix: Nothing was observed") != std::string::npos);
    CHECK(policy_overall(r) == PolicyOverall::Incomplete);
    // A policy whose rules are all NOT_APPLICABLE verified nothing: INCOMPLETE (exit 3), never NO_DRIFT.
    const PolicyReport na = evaluate_policy(default_policy(), audit_all(RuleResult::NotApplicable));
    CHECK(policy_overall(na) == PolicyOverall::Incomplete && summarize(na).compliant == 0 && summarize(na).not_applicable == 7);
    CHECK(policy_exit_code(policy_overall(na)) == 3);
    CHECK(policy_exit_code(policy_overall(r)) == 3);
    // an empty audit never yields compliance
    const PolicyReport e = evaluate_policy(default_policy(), AuditReport{});
    CHECK(e.rules.size() == known_policy_rule_ids().size());
    for (const auto& x : e.rules) CHECK(x.verdict == PolicyVerdict::Incomplete);
    CHECK(policy_overall(e) == PolicyOverall::Incomplete);
}

AuditReport sig_audit(RuleResult rr, const char* age) {
    AuditReport a;
    std::vector<std::pair<std::string, std::string>> ev;
    if (age) ev.emplace_back("signature_age_days", age);
    a.findings.push_back(finding("META-AV-004", rr, ev));
    return a;
}

void test_signature_limit() {
    auto verdict = [](const AuditReport& a, int limit) {
        PolicyRule pr{"META-AV-004", limit};
        return evaluate_policy(policy_of({pr}), a).rules[0].verdict;
    };
    CHECK(verdict(sig_audit(RuleResult::Pass, "2"), 3) == PolicyVerdict::Compliant);
    CHECK(verdict(sig_audit(RuleResult::Pass, "3"), 3) == PolicyVerdict::Compliant);  // inclusive
    CHECK(verdict(sig_audit(RuleResult::Fail, "4"), 3) == PolicyVerdict::Drift);
    // The policy's limit can only tighten: stricter than the audit's PASS, never looser than its FAIL.
    CHECK(verdict(sig_audit(RuleResult::Pass, "2"), 1) == PolicyVerdict::Drift);
    CHECK(verdict(sig_audit(RuleResult::Pass, "3"), 2) == PolicyVerdict::Drift);
    CHECK(verdict(sig_audit(RuleResult::Pass, "2"), 2) == PolicyVerdict::Compliant);
    for (int age = 4; age <= 400; ++age)  // audit FAIL (age > 3): no admissible limit (1..3) makes it COMPLIANT
        for (int limit = kMinSignatureAgeParam; limit <= kMaxSignatureAgeParam; ++limit)
            CHECK(verdict(sig_audit(RuleResult::Fail, std::to_string(age).c_str()), limit) == PolicyVerdict::Drift);
    // No usable age: INCOMPLETE, even if the audit said PASS.
    CHECK(verdict(sig_audit(RuleResult::Pass, nullptr), 3) == PolicyVerdict::Incomplete);
    CHECK(verdict(sig_audit(RuleResult::Fail, nullptr), 3) == PolicyVerdict::Incomplete);
    for (const char* bad : {"", "abc", "-1", "1.5", "1 ", " 1", "99999999999999999999", "0x2"})
        CHECK(verdict(sig_audit(RuleResult::Pass, bad), 3) == PolicyVerdict::Incomplete);
    // UNKNOWN / NOT_APPLICABLE are never decided by a leftover age
    CHECK(verdict(sig_audit(RuleResult::Unknown, "1"), 3) == PolicyVerdict::Incomplete);
    CHECK(verdict(sig_audit(RuleResult::NotApplicable, "1"), 3) == PolicyVerdict::NotApplicable);
    // Without a policy limit the audit's own verdict decides.
    PolicyRule plain{"META-AV-004", std::nullopt};
    CHECK(evaluate_policy(policy_of({plain}), sig_audit(RuleResult::Pass, "2")).rules[0].verdict == PolicyVerdict::Compliant);
    CHECK(evaluate_policy(policy_of({plain}), sig_audit(RuleResult::Fail, "9")).rules[0].verdict == PolicyVerdict::Drift);
}

void test_overall_and_exit() {
    auto overall_of = [](std::vector<RuleResult> results) {
        AuditReport a;
        std::vector<PolicyRule> rules;
        const auto& ids = known_policy_rule_ids();
        for (std::size_t i = 0; i < results.size(); ++i) {
            a.findings.push_back(finding(ids[i].c_str(), results[i]));
            rules.push_back({ids[i], std::nullopt});
        }
        // META-AV-004 would need an age if parameterised; these rules carry no parameter.
        return policy_overall(evaluate_policy(policy_of(rules), a));
    };
    using R = RuleResult;
    CHECK(overall_of({R::Pass, R::Pass}) == PolicyOverall::NoDrift);
    CHECK(overall_of({R::Pass, R::NotApplicable}) == PolicyOverall::NoDrift);
    CHECK(overall_of({R::Pass, R::Fail}) == PolicyOverall::Drift);
    CHECK(overall_of({R::Pass, R::Unknown}) == PolicyOverall::Incomplete);
    CHECK(overall_of({R::Unknown, R::Fail}) == PolicyOverall::Drift);  // confirmed drift outranks unobserved
    CHECK(overall_of({}) == PolicyOverall::Incomplete);                // nothing evaluated is never "no drift"
    CHECK(policy_exit_code(PolicyOverall::NoDrift) == 0);
    CHECK(policy_exit_code(PolicyOverall::Drift) == 1);
    CHECK(policy_exit_code(PolicyOverall::Incomplete) == 3);
    // the report copies the audit header
    const PolicyReport r = evaluate_policy(default_policy(), audit_all(R::Pass));
    CHECK(r.hostname == "host" && r.observed_at_utc == "2026-11-02T00:00:00Z" && r.platform.kind == "client");
    CHECK(r.policy_id == "meta-default-baseline" && r.policy_version == 1 && r.policy_source == "built-in");
}

// A real audit over a (fake) machine state: public firewall off -> exactly that rule drifts.
CheckResult mkc(const char* id, State s) {
    CheckResult c;
    c.check_id = id;
    c.observed_at_utc = "2026-11-02T00:00:00Z";
    c.state = s;
    c.source = "fake";
    if (s == State::Unknown) c.error_code = "HRESULT:0x80004005";
    return c;
}

AuditInput healthy_machine() {
    AuditInput in;
    in.status.hostname = "host";
    in.status.observed_at_utc = "2026-11-02T00:00:00Z";
    in.status.platform = {"windows", "10.0.26200", "client"};
    in.status.checks.push_back(mkc(kIdFwDomain, State::Enabled));
    in.status.checks.push_back(mkc(kIdFwPrivate, State::Enabled));
    in.status.checks.push_back(mkc(kIdFwPublic, State::Enabled));
    in.status.checks.push_back(mkc(kIdWsc, State::Good));
    DefenderRaw raw;
    raw.antivirus_enabled = true;
    raw.realtime_enabled = true;
    raw.running_mode = "Normal";
    raw.signature_age_days = 1;
    raw.signature_version = "1.2.3.4";
    for (auto&& c : interpret_defender(raw, State::Good, "2026-11-02T00:00:00Z")) in.status.checks.push_back(c);
    in.av_products.obs = Obs::Observed;
    in.av_products.products = {{"Windows Defender", 0x41000}};
    return in;
}

void test_end_to_end_drift() {
    {
        const PolicyReport r = evaluate_policy(default_policy(), run_audit(healthy_machine()));
        CHECK(policy_overall(r) == PolicyOverall::NoDrift);
        CHECK(summarize(r).compliant == 7 && summarize(r).drift == 0);
    }
    {
        AuditInput in = healthy_machine();
        for (auto& c : in.status.checks)
            if (c.check_id == kIdFwPublic) c.state = State::Disabled;
        const PolicyReport r = evaluate_policy(default_policy(), run_audit(in));
        CHECK(policy_overall(r) == PolicyOverall::Drift);
        CHECK(policy_exit_code(policy_overall(r)) == 1);
        const PolicyRuleResult* x = by_id(r, "META-FW-003");
        CHECK(x && x->verdict == PolicyVerdict::Drift && x->observed == RuleResult::Fail);
        CHECK(x && !x->evidence.empty() && !x->sources.empty() && !x->remediation.empty());
        CHECK(summarize(r).drift == 1 && summarize(r).compliant == 6);
        const PolicyRuleResult* ok = by_id(r, "META-FW-001");
        CHECK(ok && ok->verdict == PolicyVerdict::Compliant);
    }
    {
        AuditInput in = healthy_machine();
        for (auto& c : in.status.checks)
            if (c.check_id == kIdFwDomain) c = mkc(kIdFwDomain, State::Unknown);
        const PolicyReport r = evaluate_policy(default_policy(), run_audit(in));
        const PolicyRuleResult* x = by_id(r, "META-FW-001");
        CHECK(x && x->verdict == PolicyVerdict::Incomplete);  // unobservable is never compliant
        CHECK(policy_overall(r) == PolicyOverall::Incomplete);
    }
    {
        // A policy stricter than the audit: signatures 3 days old pass the audit (limit 3) but drift under
        // a policy limit of 2. The difference is explained, never silent.
        AuditInput in = healthy_machine();
        for (auto& c : in.status.checks)
            if (c.check_id == kIdDefenderAv)
                for (auto& [k, v] : c.evidence)
                    if (k == "signature_age_days") v = "3";
        const AuditReport a = run_audit(in);
        const PolicyRuleResult* dflt = by_id(evaluate_policy(default_policy(), a), "META-AV-004");
        CHECK(dflt && dflt->verdict == PolicyVerdict::Compliant);
        const PolicyReport strict = evaluate_policy(policy_of({{"META-AV-004", 2}}), a);
        CHECK(strict.rules[0].verdict == PolicyVerdict::Drift);
        CHECK(strict.rules[0].detail.find("audit threshold 3") != std::string::npos);
        CHECK(strict.rules[0].detail.find("audit itself says PASS") != std::string::npos);
    }
}

// ---- path validation ----------------------------------------------------------------------------

void test_paths() {
    for (const char* ok : {"policy.json", "C:\\policies\\p.json", "c:/p.json", "sub\\dir\\p.json", "..\\p.json", ".\\p.json", "p (1).json", "é.json"})
        CHECK(valid_policy_path(ok));
    for (const char* bad : {"", "\\\\server\\share\\p.json", "//server/share/p.json", "\\\\?\\C:\\p.json", "\\\\.\\C:\\p.json", "\\\\.\\pipe\\x",
                            "\\p.json", "/p.json", "C:p.json", "C:", "p.json:stream", "C:\\p.json:$DATA", "C:\\a:b\\p.json", "1:\\p.json",
                            "p*.json", "p?.json", "p<.json", "p>.json", "p|.json", "\"p.json\"", "p\x01.json", "p\n.json", "p\x7f.json"})
        CHECK(!valid_policy_path(bad));
    CHECK(valid_policy_path(std::string(260, 'a')));
    CHECK(!valid_policy_path(std::string(261, 'a')));
    std::string why;
    CHECK(!valid_policy_path("\\\\x\\y", &why) && !why.empty());
}

// ---- identity (SHA-256) and coverage --------------------------------------------------------------

void test_sha_and_coverage() {
    // FIPS 180-4 / NIST known answers
    CHECK(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(sha256_hex(std::string(1000000, 'a')) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    // padding boundaries: lengths 55, 56, 63, 64, 65 all produce 64 hex characters and differ pairwise
    std::set<std::string> seen;
    for (std::size_t n : {55u, 56u, 63u, 64u, 65u, 119u, 120u}) {
        const std::string h = sha256_hex(std::string(n, 'x'));
        CHECK(h.size() == 64);
        CHECK(seen.insert(h).second);
    }
    CHECK(sha256_hex(std::string(55, 'a')) == "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    CHECK(sha256_hex(std::string(56, 'a')) == "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    CHECK(sha256_hex(std::string(64, 'a')) == "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");

    // The hash is over the exact bytes read (BOM and whitespace included), file source only.
    const std::string text = doc(kOneRule);
    const auto a = parse_policy(text);
    const auto b = parse_policy(text);
    const auto c = parse_policy(text + " ");
    const auto d = parse_policy("\xEF\xBB\xBF" + text);
    CHECK(a.ok && b.ok && c.ok && d.ok);
    CHECK(a.policy.sha256 == sha256_hex(text) && a.policy.sha256 == b.policy.sha256);
    CHECK(c.policy.sha256 != a.policy.sha256 && d.policy.sha256 == sha256_hex("\xEF\xBB\xBF" + text));
    CHECK(a.policy.sha256.size() == 64);
    // built-in baseline: an identifier, not a hash of a file
    CHECK(default_policy().sha256 == "builtin:meta-default-baseline:v1");
    // a rejected document carries no identity
    CHECK(parse_policy("{").policy.sha256.empty());

    // Coverage: named rules out of the audit's rules, in the report.
    const AuditReport all = audit_all(RuleResult::Pass);
    const PolicyReport full = evaluate_policy(default_policy(), all);
    CHECK(full.rules_covered == 7 && full.rules_total == 7 && full.policy_sha256 == "builtin:meta-default-baseline:v1");
    const PolicyReport part = evaluate_policy(policy_of({{"META-FW-001", std::nullopt}, {"META-AV-001", std::nullopt}}), all);
    CHECK(part.rules_covered == 2 && part.rules_total == 7);
    const std::string t = render_policy_text(part, "1");
    CHECK(t.find("Coverage: 2/7 rules covered (rules not named by the policy are NOT checked)") != std::string::npos);
    const std::string j = render_policy_json(part, "1");
    CHECK(j.find("\"coverage\":{\"rules_covered\":2,\"rules_total\":7}") != std::string::npos);
}

// ---- CLI parsing --------------------------------------------------------------------------------

ParsedArgs parse(std::vector<std::string> a) {
    std::vector<std::string_view> v(a.begin(), a.end());
    return parse_args(v);
}

void test_args() {
    {
        const ParsedArgs p = parse({"policy", "check"});
        CHECK(p.command == Command::Policy && p.policy == PolicyCommand::Check && !p.json && p.policy_file.empty());
    }
    {
        const ParsedArgs p = parse({"policy", "check", "--json", "--policy-file", "C:\\p.json"});
        CHECK(p.command == Command::Policy && p.json && p.policy_file == "C:\\p.json");
    }
    {
        const ParsedArgs p = parse({"policy", "check", "--policy-file", "p.json", "--json"});
        CHECK(p.command == Command::Policy && p.json && p.policy_file == "p.json");
    }
    {
        const ParsedArgs p = parse({"policy", "default"});
        CHECK(p.command == Command::Policy && p.policy == PolicyCommand::Default);
    }
    const std::vector<std::vector<std::string>> bad = {
        {"policy"}, {"policy", "bogus"}, {"policy", "fix"}, {"policy", "check", "--bogus"}, {"policy", "check", "extra"},
        {"policy", "check", "--json", "--json"}, {"policy", "check", "--policy-file"}, {"policy", "check", "--policy-file", "--json"},
        {"policy", "check", "--policy-file", "a", "--policy-file", "b"}, {"policy", "check", "--policy-file", ""},
        {"policy", "check", "--policy-file", "\\\\srv\\share\\p.json"}, {"policy", "check", "--policy-file", "p.json:s"},
        {"policy", "check", "--policy-file", "p*.json"}, {"policy", "check", "--fix"}, {"policy", "check", "--apply"},
        {"policy", "check", "--dry-run"}, {"policy", "default", "--json"}, {"policy", "default", "extra"},
        {"policy", "--json"}, {"policy", "check", "--policy"}, {"policy", "check", "--policy-file=p.json"}};
    for (const auto& b : bad) {
        const ParsedArgs p = parse(b);
        CHECK(p.command == Command::Invalid && !p.error.empty());
    }
    // Policy has no verb that changes anything: the help text mentions no remediation for it.
    const std::string u = usage_text("1.0.0");
    CHECK(u.find("policy check") != std::string::npos && u.find("policy default") != std::string::npos);
}

// ---- rendering ----------------------------------------------------------------------------------

PolicyReport hostile_report() {
    AuditReport a = audit_all(RuleResult::Pass);
    a.hostname = "a\"b\\c";
    a.findings[2].result = RuleResult::Fail;
    a.findings[2].sources = {"src\"x"};
    a.findings[2].evidence.emplace_back("detail", "line1\nline2 \x1b[31m red \"q\" \\ end");
    PolicyReport r = evaluate_policy(default_policy(), a);
    return r;
}

void test_render() {
    const PolicyReport r = hostile_report();
    const std::string j = render_policy_json(r, "9.9.9");
    CHECK(j.size() > 100 && j.back() == '\n');
    CHECK(j.find('\n') == j.size() - 1);  // one line
    CHECK(j.find("\"command\":\"policy check\"") != std::string::npos);
    CHECK(j.find("\"overall\":\"DRIFT\"") != std::string::npos);
    CHECK(j.find("\"verdict\":\"DRIFT\"") != std::string::npos);
    CHECK(j.find("\"expected\":{\"result\":\"PASS\"") != std::string::npos);
    CHECK(j.find("\"max_signature_age_days\":3") != std::string::npos);
    CHECK(j.find("\x1b") == std::string::npos);  // control characters are escaped
    const JsonParseResult jp = json_parse(j, 16);
    CHECK(jp.ok);
    if (jp.ok) {
        const JsonValue* rules = jp.value.find("rules");
        CHECK(rules && rules->type == JsonValue::Type::Array && rules->array.size() == 7);
        const JsonValue* s = jp.value.find("summary");
        CHECK(s && s->find("drift") && s->find("drift")->integer == 1 && s->find("compliant")->integer == 6);
        CHECK(jp.value.find("hostname") && jp.value.find("hostname")->string == "a\"b\\c");
        const JsonValue* pol = jp.value.find("policy");
        CHECK(pol && pol->find("source") && pol->find("source")->string == "built-in");
        // No file path anywhere: the policy block has exactly these keys.
        CHECK(pol && pol->object.size() == 5);
        CHECK(pol && pol->find("policy_sha256") && pol->find("policy_sha256")->string == "builtin:meta-default-baseline:v1");
        const JsonValue* cov = jp.value.find("coverage");
        CHECK(cov && cov->find("rules_covered") && cov->find("rules_covered")->integer == 7 &&
              cov->find("rules_total") && cov->find("rules_total")->integer == 7);
    }
    CHECK(render_policy_text(r, "9.9.9").find("Coverage: 7/7 rules covered") != std::string::npos);
    CHECK(render_policy_text(r, "9.9.9").find("Policy SHA-256: builtin:meta-default-baseline:v1") != std::string::npos);
    const std::string t = render_policy_text(r, "9.9.9");
    CHECK(t.find("[DRIFT] META-FW-003") != std::string::npos);
    CHECK(t.find("expected: PASS") != std::string::npos && t.find("observed: FAIL") != std::string::npos);
    CHECK(t.find("(signature age <= 3 days)") != std::string::npos);
    CHECK(t.find("Overall: DRIFT") != std::string::npos);
    CHECK(t.find("source: ") != std::string::npos);
    CHECK(t.find('\x1b') == std::string::npos);  // terminal control characters neutralised in text mode
}

int emit_hostile_json() {
    std::fputs(render_policy_json(hostile_report(), "9.9.9").c_str(), stdout);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--emit-json") return emit_hostile_json();
    test_default_policy();
    test_parse_valid();
    test_parse_hostile();
    test_verdict_table();
    test_missing_rule_is_incomplete();
    test_signature_limit();
    test_overall_and_exit();
    test_end_to_end_drift();
    test_paths();
    test_sha_and_coverage();
    test_args();
    test_render();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
