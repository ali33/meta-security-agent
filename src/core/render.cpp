#include "render.hpp"

#include <format>

#include "json.hpp"

namespace metasec {

std::string format_utc(std::chrono::system_clock::time_point tp) {
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::floor<std::chrono::seconds>(tp));
}

namespace {

void put_str(std::string& o, std::string_view s) {
    o += '"';
    o += json_escape(s);
    o += '"';
}

void put_kv(std::string& o, std::string_view k, std::string_view v) {
    put_str(o, k);
    o += ':';
    put_str(o, v);
}

}  // namespace

std::string render_status_json(const StatusReport& r, const std::string& version) {
    std::string o;
    o += '{';
    o += "\"schema_version\":" + std::to_string(kSchemaVersion) + ',';
    put_kv(o, "product", kProduct); o += ',';
    put_kv(o, "version", version); o += ',';
    put_kv(o, "mode", "standalone"); o += ',';
    put_kv(o, "hostname", r.hostname); o += ',';
    put_kv(o, "observed_at_utc", r.observed_at_utc); o += ',';
    o += "\"platform\":{";
    put_kv(o, "os", r.platform.os); o += ',';
    put_kv(o, "version", r.platform.version); o += ',';
    put_kv(o, "kind", r.platform.kind);
    o += "},\"checks\":[";
    bool first = true;
    for (const auto& c : r.checks) {
        if (!first) o += ',';
        first = false;
        o += '{';
        put_kv(o, "check_id", c.check_id); o += ',';
        put_kv(o, "name", c.check_id); o += ',';  // alias kept from the MVP-0 skeleton contract
        put_kv(o, "observed_at_utc", c.observed_at_utc); o += ',';
        put_kv(o, "state", to_string(c.state)); o += ',';
        put_kv(o, "source", c.source); o += ',';
        put_kv(o, "error_code", c.error_code); o += ',';
        put_kv(o, "error", c.error_code); o += ',';  // alias kept from the skeleton contract
        o += "\"evidence\":{";
        bool fe = true;
        for (const auto& [k, v] : c.evidence) {
            if (!fe) o += ',';
            fe = false;
            put_kv(o, k, v);
        }
        o += "}}";
    }
    o += "],";
    put_kv(o, "overall", to_string(compute_overall(r.checks)));
    o += "}\n";
    return o;
}

std::string render_status_text(const StatusReport& r, const std::string& version) {
    std::string o;
    o += std::format("{} v{} | Standalone | Read-only\n", kProduct, version);
    o += std::format("Host: {}\n", r.hostname);
    o += std::format("Platform: {} {} ({})\n", r.platform.os, r.platform.version, r.platform.kind);
    o += std::format("Observed: {}\n", r.observed_at_utc);
    for (const auto& c : r.checks) {
        std::string line = std::format("{:<44}{}", c.check_id, to_string(c.state));
        if (!c.error_code.empty()) line += " (" + c.error_code + ")";
        for (const auto& [k, v] : c.evidence) line += std::format(" [{}={}]", k, v);
        o += line + '\n';
    }
    o += std::format("Overall: {} (an observation summary, not an antivirus protection verdict)\n",
                     to_string(compute_overall(r.checks)));
    return o;
}

}  // namespace metasec
