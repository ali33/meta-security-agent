#pragma once
// Local baseline policy (MVP-5): a small, versioned, strictly parsed file saying which audit rules
// must PASS on this machine, and a pure comparison of that expectation with an AuditReport.
// No Windows headers, no I/O, no side effects. Reading the file is the Windows layer's job
// (src/win/policy_file_win.cpp); this module only sees its bytes.
//
// A rule that could not be observed is INCOMPLETE, never COMPLIANT. A rule the policy names but the
// audit did not produce is INCOMPLETE as well.
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "audit.hpp"
#include "types.hpp"

namespace metasec {

inline constexpr int kPolicySchemaVersion = 1;
inline constexpr std::size_t kMaxPolicyBytes = 64 * 1024;  // a file larger than this is refused unread
inline constexpr std::size_t kMaxPolicyRules = 32;
inline constexpr int kMaxPolicyId = 64;
inline constexpr int kMaxPolicyVersion = 1000000;
inline constexpr int kMinSignatureAgeParam = 1;
// A policy may only TIGHTEN the audit's signature-age limit, never loosen it: the maximum is the
// audit's own kSignatureMaxAgeDays. A larger value is a policy error.
inline constexpr int kMaxSignatureAgeParam = static_cast<int>(kSignatureMaxAgeDays);
inline constexpr const char* kSignatureAgeRule = "META-AV-004";

// Rule ids a policy may name (exactly the rules run_audit produces, same order).
const std::vector<std::string>& known_policy_rule_ids();

struct PolicyRule {
    std::string rule_id;
    // META-AV-004 only: the policy's own limit for signature age. Absent = the audit's built-in limit.
    // When present it is between 1 and the audit's own threshold (it can only tighten), so the verdict
    // can be stricter than the audit's result, never looser; the report's `detail` says so.
    std::optional<int> max_signature_age_days;
};

struct Policy {
    std::string policy_id;
    int policy_version = 0;
    std::string source;  // "built-in" or "file" (never a path: paths can carry user names)
    // Identity of the exact bytes this policy was parsed from: SHA-256 hex of the file bytes as read
    // (BOM included), or "builtin:<policy_id>:v<policy_version>" for the built-in baseline. Identification
    // only, NOT a signature: it proves nothing about who wrote the file.
    std::string sha256;
    std::vector<PolicyRule> rules;
};

struct PolicyParseResult {
    bool ok = false;
    std::string error;  // short; names the offending key at most (sanitized), never echoes values
    Policy policy;
};

// Strict parse of a policy document (schema in docs/CLI.md). Fails closed on anything unexpected:
// unknown keys, unknown or duplicate rule ids, wrong types, out-of-range numbers, trailing text, files
// over kMaxPolicyBytes.
PolicyParseResult parse_policy(std::string_view text);

// The built-in baseline: every audit rule must PASS; signature age limit = kSignatureMaxAgeDays.
const char* default_policy_json();
Policy default_policy();

// Command-line path check (pure): non-empty, short, no control characters, no wildcards, no UNC or
// device path, no alternate data stream. Does not touch the file system.
bool valid_policy_path(std::string_view path, std::string* why = nullptr);

enum class PolicyVerdict { Compliant, Drift, Incomplete, NotApplicable };
const char* to_string(PolicyVerdict v);

struct PolicyRuleResult {
    std::string rule_id;
    int rule_version = 0;
    std::string title;
    Severity severity = Severity::Medium;
    std::string remediation;
    // Expected: the audit rule must PASS (v1 has no other expectation), optionally with a limit.
    std::optional<int> max_signature_age_days;
    // Observed: the audit result and its evidence, copied from the finding. UNKNOWN when the audit
    // did not produce the rule.
    RuleResult observed = RuleResult::Unknown;
    std::vector<std::pair<std::string, std::string>> evidence;
    std::vector<std::string> check_ids;
    std::vector<std::string> sources;
    PolicyVerdict verdict = PolicyVerdict::Incomplete;
    std::string detail;  // one sentence: why this verdict
};

struct PolicyReport {
    std::string hostname;
    std::string observed_at_utc;
    PlatformInfo platform;
    std::string policy_id;
    int policy_version = 0;
    std::string policy_source;
    std::string policy_sha256;
    // Coverage: how many of the audit's rules this policy names (n of total). A policy that omits
    // rules is only as strict as its author; this makes the omission visible.
    int rules_covered = 0;
    int rules_total = 0;
    std::vector<PolicyRuleResult> rules;
};

// Pure comparison. Order follows the policy.
PolicyReport evaluate_policy(const Policy& policy, const AuditReport& audit);

struct PolicySummary {
    int compliant = 0, drift = 0, incomplete = 0, not_applicable = 0;
};
PolicySummary summarize(const PolicyReport& r);

// Drift: at least one confirmed violation. Incomplete: no drift, but something is unobserved (or
// the policy has no rules, or no rule is COMPLIANT). NoDrift: no drift, nothing unobserved, and at
// least one rule affirmatively COMPLIANT (NOT_APPLICABLE alone verifies nothing).
enum class PolicyOverall { NoDrift, Drift, Incomplete };
const char* to_string(PolicyOverall o);
PolicyOverall policy_overall(const PolicyReport& r);

// Same precedence as audit: a confirmed drift (1) outranks incomplete observation (3).
int policy_exit_code(PolicyOverall o);

}  // namespace metasec
