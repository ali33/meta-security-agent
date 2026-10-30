#pragma once
// Audit engine (MVP-1): pure rules over already-observed data. No Windows headers, no I/O.
// Every rule is a deterministic function of AuditInput, so each outcome is unit-testable
// with fakes. UNKNOWN (we could not observe) is never converted to PASS.
#include <string>
#include <utility>
#include <vector>

#include "types.hpp"

namespace metasec {

// Signature-freshness threshold (rule META-AV-004), in days. Microsoft publishes Defender
// security intelligence several times a day; 3 days tolerates a long weekend or a laptop
// that was off, while 4+ days means automatic updates are not working. Changing this
// constant is a rule change: bump kRuleVersionSignatureAge.
inline constexpr long long kSignatureMaxAgeDays = 3;

enum class RuleResult { Pass, Fail, Unknown, NotApplicable };
const char* to_string(RuleResult r);

// Severity of the finding if the rule FAILs (reported for every result).
enum class Severity { Low, Medium, High, Critical };
const char* to_string(Severity s);

// How trustworthy the observation of the registered-AV list was.
enum class Obs { Observed, Unknown, NotSupported };
const char* to_string(Obs o);

// One entry of WMI ROOT\SecurityCenter2 : AntiVirusProduct (client SKUs only).
struct AvProduct {
    std::string name;
    long long product_state = 0;  // raw productState
};

struct AvProductsObservation {
    Obs obs = Obs::Unknown;
    std::string error_code;  // set when obs != Observed
    std::string source = "WMI:ROOT\\SecurityCenter2:AntiVirusProduct";
    std::vector<AvProduct> products;  // meaningful only when obs == Observed (may be empty)
};

// Decoded "on/off" nibble of AntiVirusProduct.productState (bits 12..15). The encoding is
// widely used but not documented by Microsoft, so anything outside 0..3 is Unrecognized.
enum class AvActivity { Off, On, Snoozed, Expired, Unrecognized };
const char* to_string(AvActivity a);
AvActivity av_activity(long long product_state);

struct AuditInput {
    StatusReport status;
    AvProductsObservation av_products;
};

inline constexpr int kRuleVersionFirewall = 1;
inline constexpr int kRuleVersionWscHealth = 1;
inline constexpr int kRuleVersionActiveAv = 1;
inline constexpr int kRuleVersionDefenderRealtime = 1;
inline constexpr int kRuleVersionSignatureAge = 1;

struct Finding {
    std::string rule_id;  // stable, e.g. META-FW-001
    int rule_version = 1;
    std::string title;
    RuleResult result = RuleResult::Unknown;
    Severity severity = Severity::Medium;
    std::string remediation;  // what a human can do; the agent never changes settings
    std::vector<std::pair<std::string, std::string>> evidence;
    std::vector<std::string> check_ids;  // provenance: inputs the verdict depends on
    std::vector<std::string> sources;    // provenance: data sources behind those inputs
};

struct AuditReport {
    std::string hostname;
    std::string observed_at_utc;
    PlatformInfo platform;
    std::vector<Finding> findings;
};

// Evaluates every rule. Order is fixed: FW-001..003, AV-001..004.
AuditReport run_audit(const AuditInput& in);

// Individual rules (exposed for tests).
Finding rule_firewall(const AuditInput& in, const char* check_id);
Finding rule_wsc_health(const AuditInput& in);
Finding rule_active_av(const AuditInput& in);
Finding rule_defender_realtime(const AuditInput& in);
Finding rule_signature_age(const AuditInput& in);

struct AuditSummary {
    int pass = 0, fail = 0, unknown = 0, not_applicable = 0;
};
AuditSummary summarize(const AuditReport& r);

// Findings: at least one confirmed FAIL. Incomplete: no FAIL, but at least one rule is
// UNKNOWN (or there are no rules at all). NoFindings: only PASS / NOT_APPLICABLE.
enum class AuditOverall { NoFindings, Findings, Incomplete };
const char* to_string(AuditOverall o);
AuditOverall audit_overall(const AuditReport& r);

// Confirmed FAIL (1) takes precedence over incomplete observation (3): a known violation
// must never be hidden by an unrelated unknown. See docs/CLI.md.
int audit_exit_code(AuditOverall o);

}  // namespace metasec
