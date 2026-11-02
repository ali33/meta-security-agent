#include "policy.hpp"

#include <charconv>
#include <set>

#include "cli.hpp"
#include "json.hpp"

namespace metasec {

const std::vector<std::string>& known_policy_rule_ids() {
    static const std::vector<std::string> ids = {"META-FW-001", "META-FW-002", "META-FW-003", "META-AV-001",
                                                 "META-AV-002", "META-AV-003", "META-AV-004"};
    return ids;
}

const char* to_string(PolicyVerdict v) {
    switch (v) {
        case PolicyVerdict::Compliant: return "COMPLIANT";
        case PolicyVerdict::Drift: return "DRIFT";
        case PolicyVerdict::Incomplete: return "INCOMPLETE";
        case PolicyVerdict::NotApplicable: return "NOT_APPLICABLE";
    }
    return "INCOMPLETE";
}

const char* to_string(PolicyOverall o) {
    switch (o) {
        case PolicyOverall::NoDrift: return "NO_DRIFT";
        case PolicyOverall::Drift: return "DRIFT";
        case PolicyOverall::Incomplete: return "INCOMPLETE";
    }
    return "INCOMPLETE";
}

const char* default_policy_json() {
    return "{\n"
           "  \"schema_version\": 1,\n"
           "  \"policy_id\": \"meta-default-baseline\",\n"
           "  \"policy_version\": 1,\n"
           "  \"rules\": [\n"
           "    {\"rule_id\": \"META-FW-001\", \"expect\": \"PASS\"},\n"
           "    {\"rule_id\": \"META-FW-002\", \"expect\": \"PASS\"},\n"
           "    {\"rule_id\": \"META-FW-003\", \"expect\": \"PASS\"},\n"
           "    {\"rule_id\": \"META-AV-001\", \"expect\": \"PASS\"},\n"
           "    {\"rule_id\": \"META-AV-002\", \"expect\": \"PASS\"},\n"
           "    {\"rule_id\": \"META-AV-003\", \"expect\": \"PASS\"},\n"
           "    {\"rule_id\": \"META-AV-004\", \"expect\": \"PASS\", \"max_signature_age_days\": 3}\n"
           "  ]\n"
           "}\n";
}

Policy default_policy() {
    PolicyParseResult r = parse_policy(default_policy_json());
    Policy p = std::move(r.policy);
    p.source = "built-in";
    return p;
}

namespace {

bool valid_policy_id(const std::string& s) {
    if (s.empty() || s.size() > static_cast<std::size_t>(kMaxPolicyId)) return false;
    for (char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                        c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

bool is_int_in(const JsonValue& v, long long lo, long long hi) {
    return v.type == JsonValue::Type::Number && v.is_integer && v.integer >= lo && v.integer <= hi;
}

PolicyParseResult fail(std::string msg) {
    PolicyParseResult r;
    r.error = std::move(msg);
    return r;
}

PolicyParseResult parse_rule(const JsonValue& v, std::size_t index, PolicyRule& out) {
    const std::string at = "rules[" + std::to_string(index) + "]: ";
    if (v.type != JsonValue::Type::Object) return fail(at + "must be an object");
    const JsonValue* id = nullptr;
    const JsonValue* expect = nullptr;
    const JsonValue* age = nullptr;
    for (const auto& [k, val] : v.object) {
        if (k == "rule_id") id = &val;
        else if (k == "expect") expect = &val;
        else if (k == "max_signature_age_days") age = &val;
        else return fail(at + "unknown key: " + sanitize_for_display(k));
    }
    if (!id || id->type != JsonValue::Type::String) return fail(at + "rule_id must be a string");
    bool known = false;
    for (const auto& k : known_policy_rule_ids()) known = known || k == id->string;
    if (!known) return fail(at + "unknown rule id: " + sanitize_for_display(id->string));
    if (!expect || expect->type != JsonValue::Type::String) return fail(at + "expect must be a string");
    if (expect->string != "PASS") return fail(at + "expect must be \"PASS\" (the only expectation in schema 1)");
    out.rule_id = id->string;
    if (age) {
        if (out.rule_id != kSignatureAgeRule)
            return fail(at + "max_signature_age_days is only valid for " + std::string(kSignatureAgeRule));
        if (!is_int_in(*age, kMinSignatureAgeParam, kMaxSignatureAgeParam))
            return fail(at + "max_signature_age_days must be an integer from " + std::to_string(kMinSignatureAgeParam) +
                        " to " + std::to_string(kMaxSignatureAgeParam));
        out.max_signature_age_days = static_cast<int>(age->integer);
    }
    PolicyParseResult ok;
    ok.ok = true;
    return ok;
}

}  // namespace

PolicyParseResult parse_policy(std::string_view text) {
    if (text.size() > kMaxPolicyBytes) return fail("policy is larger than " + std::to_string(kMaxPolicyBytes) + " bytes");
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF && static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF)
        text.remove_prefix(3);  // UTF-8 byte order mark (Windows editors add it)
    if (text.empty()) return fail("policy is empty");
    const JsonParseResult jr = json_parse(text, 8);
    if (!jr.ok) return fail("policy is not valid JSON: " + jr.error);
    const JsonValue& root = jr.value;
    if (root.type != JsonValue::Type::Object) return fail("policy must be a JSON object");

    const JsonValue* schema = nullptr;
    const JsonValue* id = nullptr;
    const JsonValue* version = nullptr;
    const JsonValue* rules = nullptr;
    for (const auto& [k, val] : root.object) {
        if (k == "schema_version") schema = &val;
        else if (k == "policy_id") id = &val;
        else if (k == "policy_version") version = &val;
        else if (k == "rules") rules = &val;
        else return fail("unknown key: " + sanitize_for_display(k));
    }
    if (!schema || !is_int_in(*schema, 1, 1000000)) return fail("schema_version must be an integer");
    if (schema->integer != kPolicySchemaVersion)
        return fail("unsupported policy schema_version (this build reads " + std::to_string(kPolicySchemaVersion) + ")");
    if (!id || id->type != JsonValue::Type::String || !valid_policy_id(id->string))
        return fail("policy_id must be 1-" + std::to_string(kMaxPolicyId) + " characters from A-Z a-z 0-9 - _ .");
    if (!version || !is_int_in(*version, 1, kMaxPolicyVersion))
        return fail("policy_version must be an integer from 1 to " + std::to_string(kMaxPolicyVersion));
    if (!rules || rules->type != JsonValue::Type::Array) return fail("rules must be an array");
    if (rules->array.empty()) return fail("rules must not be empty");
    if (rules->array.size() > kMaxPolicyRules) return fail("rules has more than " + std::to_string(kMaxPolicyRules) + " entries");

    PolicyParseResult out;
    out.policy.policy_id = id->string;
    out.policy.policy_version = static_cast<int>(version->integer);
    out.policy.source = "file";
    std::set<std::string> seen;
    for (std::size_t i = 0; i < rules->array.size(); ++i) {
        PolicyRule rule;
        const PolicyParseResult pr = parse_rule(rules->array[i], i, rule);
        if (!pr.ok) return pr;
        if (!seen.insert(rule.rule_id).second)
            return fail("rules[" + std::to_string(i) + "]: duplicate rule id: " + sanitize_for_display(rule.rule_id));
        out.policy.rules.push_back(std::move(rule));
    }
    out.ok = true;
    return out;
}

bool valid_policy_path(std::string_view path, std::string* why) {
    auto bad = [&](const char* m) {
        if (why) *why = m;
        return false;
    };
    if (path.empty()) return bad("path is empty");
    if (path.size() > 260) return bad("path is longer than 260 characters");
    for (char c : path) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) return bad("path contains a control character");
        if (c == '*' || c == '?' || c == '<' || c == '>' || c == '|' || c == '"') return bad("path contains a wildcard or reserved character");
    }
    if (path.front() == '\\' || path.front() == '/') return bad("UNC, device and rooted-without-drive paths are not accepted");
    for (std::size_t i = 0; i < path.size(); ++i) {
        if (path[i] != ':') continue;
        const bool drive = i == 1 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
                           path.size() > 2 && (path[2] == '\\' || path[2] == '/');
        if (!drive) return bad("only a drive letter may use ':' (alternate data streams and drive-relative paths are not accepted)");
    }
    return true;
}

namespace {

const std::string* find_ev(const Finding& f, const char* key) {
    for (const auto& [k, v] : f.evidence)
        if (k == key) return &v;
    return nullptr;
}

bool parse_nonneg(const std::string& s, long long& out) {
    long long v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc() || p != s.data() + s.size() || v < 0) return false;
    out = v;
    return true;
}

}  // namespace

PolicyReport evaluate_policy(const Policy& policy, const AuditReport& audit) {
    PolicyReport r;
    r.hostname = audit.hostname;
    r.observed_at_utc = audit.observed_at_utc;
    r.platform = audit.platform;
    r.policy_id = policy.policy_id;
    r.policy_version = policy.policy_version;
    r.policy_source = policy.source;
    for (const PolicyRule& pr : policy.rules) {
        PolicyRuleResult res;
        res.rule_id = pr.rule_id;
        res.max_signature_age_days = pr.max_signature_age_days;
        const Finding* f = nullptr;
        for (const auto& x : audit.findings)
            if (x.rule_id == pr.rule_id) {
                f = &x;
                break;
            }
        if (!f) {
            res.verdict = PolicyVerdict::Incomplete;
            res.observed = RuleResult::Unknown;
            res.detail = "the audit did not produce this rule, so nothing was observed";
            res.title = "(rule not produced by the audit)";
            res.remediation = "Nothing was observed for this rule; run `meta-sec audit` and report the missing rule.";
            res.check_ids = {"none"};
            res.sources = {"none"};
            r.rules.push_back(std::move(res));
            continue;
        }
        res.rule_version = f->rule_version;
        res.title = f->title;
        res.severity = f->severity;
        res.remediation = f->remediation;
        res.observed = f->result;
        res.evidence = f->evidence;
        res.check_ids = f->check_ids;
        res.sources = f->sources;
        switch (f->result) {
            case RuleResult::Unknown:
                res.verdict = PolicyVerdict::Incomplete;
                res.detail = "the setting could not be observed; this is not a pass";
                break;
            case RuleResult::NotApplicable:
                res.verdict = PolicyVerdict::NotApplicable;
                res.detail = "the rule does not apply on this machine";
                break;
            case RuleResult::Pass:
            case RuleResult::Fail:
                if (pr.max_signature_age_days) {
                    // The policy's own limit decides, from the age the audit observed. No usable age: unknown.
                    const std::string* age = find_ev(*f, "signature_age_days");
                    long long days = 0;
                    if (!age || !parse_nonneg(*age, days)) {
                        res.verdict = PolicyVerdict::Incomplete;
                        res.detail = "the audit reported no usable signature age, so the policy limit cannot be checked";
                    } else {
                        // The policy limit overrides the audit's own threshold; say so, so that a verdict
                        // that differs from observed.result is never unexplained.
                        const std::string note = " (policy limit " + std::to_string(*pr.max_signature_age_days) +
                                                 " day(s) replaces the audit threshold of " + std::to_string(kSignatureMaxAgeDays) +
                                                 "; the audit itself says " + to_string(f->result) + ")";
                        if (days <= *pr.max_signature_age_days) {
                            res.verdict = PolicyVerdict::Compliant;
                            res.detail = "signature age " + std::to_string(days) + " day(s) is within the policy limit" + note;
                        } else {
                            res.verdict = PolicyVerdict::Drift;
                            res.detail = "signature age " + std::to_string(days) + " day(s) exceeds the policy limit" + note;
                        }
                    }
                } else if (f->result == RuleResult::Pass) {
                    res.verdict = PolicyVerdict::Compliant;
                    res.detail = "the rule passes, as the policy expects";
                } else {
                    res.verdict = PolicyVerdict::Drift;
                    res.detail = "the policy expects this rule to pass, but it fails";
                }
                break;
        }
        r.rules.push_back(std::move(res));
    }
    return r;
}

PolicySummary summarize(const PolicyReport& r) {
    PolicySummary s;
    for (const auto& x : r.rules) {
        switch (x.verdict) {
            case PolicyVerdict::Compliant: ++s.compliant; break;
            case PolicyVerdict::Drift: ++s.drift; break;
            case PolicyVerdict::Incomplete: ++s.incomplete; break;
            case PolicyVerdict::NotApplicable: ++s.not_applicable; break;
        }
    }
    return s;
}

PolicyOverall policy_overall(const PolicyReport& r) {
    if (r.rules.empty()) return PolicyOverall::Incomplete;
    const PolicySummary s = summarize(r);
    if (s.drift > 0) return PolicyOverall::Drift;
    // Nothing affirmatively verified (no COMPLIANT rule, e.g. every rule NOT_APPLICABLE) is not a clean bill.
    return (s.incomplete > 0 || s.compliant == 0) ? PolicyOverall::Incomplete : PolicyOverall::NoDrift;
}

int policy_exit_code(PolicyOverall o) {
    switch (o) {
        case PolicyOverall::Drift: return kExitViolation;
        case PolicyOverall::Incomplete: return kExitIncomplete;
        case PolicyOverall::NoDrift: return kExitOk;
    }
    return kExitError;
}

}  // namespace metasec
