#pragma once
#include <chrono>
#include <string>

#include "audit.hpp"
#include "types.hpp"

namespace metasec {

constexpr const char* kProduct = "META Security Agent";
constexpr int kSchemaVersion = 1;

// 2026-10-30T12:34:56Z
std::string format_utc(std::chrono::system_clock::time_point tp);

// One line of JSON (+ trailing newline). Deterministic key order.
std::string render_status_json(const StatusReport& r, const std::string& version);

// Human-readable report. Never states a protection verdict.
std::string render_status_text(const StatusReport& r, const std::string& version);

// Audit report. JSON is one line with its own document type ("command":"audit", schema_version 1).
std::string render_audit_json(const AuditReport& r, const std::string& version);
std::string render_audit_text(const AuditReport& r, const std::string& version);

}  // namespace metasec
