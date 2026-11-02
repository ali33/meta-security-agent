#include "ipc_proto.hpp"

#include <format>

#include "json.hpp"
#include "render.hpp"

namespace metasec {

namespace {

// Server-side cap for free-form strings; with the worst-case 3x growth of invalid UTF-8
// (U+FFFD) it stays under what a client accepts (kIpcMaxStringField).
constexpr std::size_t kServerStringCap = 256;

std::string q(std::string_view s) { return "\"" + json_escape(truncate_utf8(std::string(s), kServerStringCap)) + "\""; }
std::string q_or_null(const std::string& s) { return s.empty() ? "null" : q(s); }

std::string head(const char* request, bool ok) {
    return std::format(R"({{"schema_version":{},"command":"service-ipc","request":"{}","ok":{})", kSchemaVersion,
                       request, ok ? "true" : "false");
}

std::string status_data(const ObserverStatus& s) {
    std::string o = std::format(
        R"({{"state":{},"health":{},"started_utc":{},"last_observation_utc":{},"polls":{},"events_total":{},)"
        R"("store_errors":{},"snapshot_errors":{},"last_error":{},"overall":{},"version":{}}})",
        q(to_string(s.state)), q(health_of(s)), q(s.started_utc), q(s.last_observation_utc), s.polls, s.events_total,
        s.store_errors, s.snapshot_errors, q(s.last_error), s.overall ? q(to_string(*s.overall)) : "null",
        q(s.version));
    return o;
}

std::string event_json(const StoredEvent& e) {
    std::string ev = "{";
    for (std::size_t i = 0; i < e.evidence.size(); ++i) {
        if (i) ev += ',';
        ev += q(e.evidence[i].first) + ":" + q(e.evidence[i].second);
    }
    ev += '}';
    return std::format(
        R"({{"id":{},"kind":{},"observed_at_utc":{},"first_observed_at_utc":{},"check_id":{},"from":{},"to":{},)"
        R"("confirmations":{},"source":{},"error_code":{},"evidence":{},"evidence_valid":{}}})",
        e.id, q(e.kind), q(e.observed_at_utc), q(e.first_observed_at_utc), q(e.check_id), q_or_null(e.from_state),
        q_or_null(e.to_state), e.confirmations, q(e.source), q(e.error_code), ev, e.evidence_valid ? "true" : "false");
}

bool is_ctl(unsigned char c) { return c < 0x20 || c == 0x7F; }

}  // namespace

const char* to_string(IpcVerb v) {
    switch (v) {
        case IpcVerb::Status: return "STATUS";
        case IpcVerb::Health: return "HEALTH";
        case IpcVerb::Events: return "EVENTS";
    }
    return "STATUS";
}

const std::array<const char*, 3>& ipc_allowed_verbs() {
    static const std::array<const char*, 3> verbs = {"STATUS", "HEALTH", "EVENTS"};
    return verbs;
}

const char* to_string(IpcErrorCode c) {
    switch (c) {
        case IpcErrorCode::EmptyRequest: return "EMPTY_REQUEST";
        case IpcErrorCode::RequestTooLong: return "REQUEST_TOO_LONG";
        case IpcErrorCode::NoNewline: return "NO_NEWLINE";
        case IpcErrorCode::EmbeddedNul: return "EMBEDDED_NUL";
        case IpcErrorCode::NonAscii: return "NON_ASCII";
        case IpcErrorCode::ControlCharacter: return "CONTROL_CHARACTER";
        case IpcErrorCode::UnknownCommand: return "UNKNOWN_COMMAND";
        case IpcErrorCode::ExtraTokens: return "EXTRA_TOKENS";
        case IpcErrorCode::BadArgument: return "BAD_ARGUMENT";
        case IpcErrorCode::StoreUnavailable: return "STORE_UNAVAILABLE";
        case IpcErrorCode::Internal: return "INTERNAL";
    }
    return "INTERNAL";
}

const char* ipc_error_message(IpcErrorCode c) {
    switch (c) {
        case IpcErrorCode::EmptyRequest: return "empty request";
        case IpcErrorCode::RequestTooLong: return "request is too long";
        case IpcErrorCode::NoNewline: return "request must be one line ending in a newline";
        case IpcErrorCode::EmbeddedNul: return "request contains a NUL byte";
        case IpcErrorCode::NonAscii: return "request must be ASCII";
        case IpcErrorCode::ControlCharacter: return "request contains a control character";
        case IpcErrorCode::UnknownCommand: return "unknown command; allowed: STATUS, HEALTH, EVENTS [n]";
        case IpcErrorCode::ExtraTokens: return "unexpected extra or empty argument";
        case IpcErrorCode::BadArgument: return "EVENTS takes one optional number from 1 to 200";
        case IpcErrorCode::StoreUnavailable: return "the event store could not be read";
        case IpcErrorCode::Internal: return "internal service error";
    }
    return "internal service error";
}

std::optional<IpcErrorCode> ipc_error_from_string(std::string_view s) {
    for (IpcErrorCode c : {IpcErrorCode::EmptyRequest, IpcErrorCode::RequestTooLong, IpcErrorCode::NoNewline,
                           IpcErrorCode::EmbeddedNul, IpcErrorCode::NonAscii, IpcErrorCode::ControlCharacter,
                           IpcErrorCode::UnknownCommand, IpcErrorCode::ExtraTokens, IpcErrorCode::BadArgument,
                           IpcErrorCode::StoreUnavailable, IpcErrorCode::Internal})
        if (s == to_string(c)) return c;
    return std::nullopt;
}

std::variant<IpcRequest, IpcParseError> parse_request(std::string_view line) {
    auto fail = [](IpcErrorCode c) { return std::variant<IpcRequest, IpcParseError>(IpcParseError{c, ipc_error_message(c)}); };
    if (line.empty()) return fail(IpcErrorCode::EmptyRequest);
    if (line.size() > kIpcMaxRequestBytes) return fail(IpcErrorCode::RequestTooLong);
    for (char c : line)
        if (c == '\0') return fail(IpcErrorCode::EmbeddedNul);
    for (char c : line)
        if (static_cast<unsigned char>(c) >= 0x80) return fail(IpcErrorCode::NonAscii);

    std::string_view body = line;
    if (body.size() >= 2 && body.substr(body.size() - 2) == "\r\n")
        body.remove_suffix(2);
    else if (body.back() == '\n')
        body.remove_suffix(1);
    else {
        // Unterminated: report a control character first if there is one, otherwise the missing newline.
        return fail(IpcErrorCode::NoNewline);
    }
    for (char c : body)
        if (is_ctl(static_cast<unsigned char>(c))) return fail(IpcErrorCode::ControlCharacter);
    if (body.empty()) return fail(IpcErrorCode::EmptyRequest);

    std::vector<std::string_view> tok;
    for (std::size_t i = 0;;) {
        const std::size_t sp = body.find(' ', i);
        tok.push_back(body.substr(i, sp == std::string_view::npos ? std::string_view::npos : sp - i));
        if (sp == std::string_view::npos) break;
        i = sp + 1;
    }
    for (const auto& t : tok)
        if (t.empty()) return fail(IpcErrorCode::ExtraTokens);

    IpcRequest r;
    if (tok[0] == "STATUS") {
        r.verb = IpcVerb::Status;
    } else if (tok[0] == "HEALTH") {
        r.verb = IpcVerb::Health;
    } else if (tok[0] == "EVENTS") {
        r.verb = IpcVerb::Events;
    } else {
        return fail(IpcErrorCode::UnknownCommand);
    }
    if (r.verb != IpcVerb::Events) {
        if (tok.size() != 1) return fail(IpcErrorCode::ExtraTokens);
        return r;
    }
    if (tok.size() > 2) return fail(IpcErrorCode::ExtraTokens);
    r.limit = kIpcDefaultEvents;
    if (tok.size() == 2) {
        const std::string_view n = tok[1];
        if (n.size() > 3 || n[0] == '0') return fail(IpcErrorCode::BadArgument);
        int v = 0;
        for (char c : n) {
            if (c < '0' || c > '9') return fail(IpcErrorCode::BadArgument);
            v = v * 10 + (c - '0');
        }
        if (v < 1 || v > kIpcMaxEvents) return fail(IpcErrorCode::BadArgument);
        r.limit = v;
    }
    return r;
}

std::string render_request(const IpcRequest& r) {
    if (r.verb == IpcVerb::Events && r.limit > 0) return std::format("EVENTS {}\n", r.limit);
    return std::string(to_string(r.verb)) + "\n";
}

const char* health_of(const ObserverStatus& s) {
    switch (s.state) {
        case ObserverState::Starting: return "STARTING";
        case ObserverState::Stopping: return "STOPPING";
        case ObserverState::Stopped: return "STOPPED";
        case ObserverState::Running: break;
    }
    if (s.store_errors > 0 || s.snapshot_errors > 0 || s.polls == 0) return "DEGRADED";
    return "OK";
}

std::string render_ipc_status(const ObserverStatus& s) {
    return head("STATUS", true) + ",\"data\":" + status_data(s) + "}\n";
}

std::string render_ipc_health(const ObserverStatus& s) {
    return head("HEALTH", true) +
           std::format(R"(,"data":{{"health":{},"state":{},"store_errors":{},"snapshot_errors":{}}}}})",
                       q(health_of(s)), q(to_string(s.state)), s.store_errors, s.snapshot_errors) +
           "\n";
}

std::string render_ipc_events(const std::vector<StoredEvent>& events, int limit) {
    const int lim = limit < 1 ? 1 : (limit > kIpcMaxEvents ? kIpcMaxEvents : limit);
    std::vector<std::string> parts;
    for (const auto& e : events) {
        if (static_cast<int>(parts.size()) >= lim) break;
        parts.push_back(event_json(e));
    }
    // Fixed overhead of the wrapper (generous) plus each event and its comma.
    constexpr std::size_t kOverhead = 256;
    std::size_t total = kOverhead;
    std::size_t keep = 0;
    while (keep < parts.size() && total + parts[keep].size() + 1 <= kIpcMaxResponseBytes) {
        total += parts[keep].size() + 1;
        ++keep;
    }
    const bool truncated = keep < parts.size();  // oldest events dropped first (they are last)
    std::string o = head("EVENTS", true);
    o += std::format(R"(,"data":{{"limit":{},"count":{},"truncated":{},"events":[)", lim, keep,
                     truncated ? "true" : "false");
    for (std::size_t i = 0; i < keep; ++i) {
        if (i) o += ',';
        o += parts[i];
    }
    o += "]}}\n";
    return o;
}

std::string render_ipc_error(IpcVerb verb, IpcErrorCode code) {
    return head(to_string(verb), false) +
           std::format(R"(,"error":{{"code":"{}","message":{}}}}})", to_string(code), q(ipc_error_message(code))) + "\n";
}

std::string render_ipc_parse_error(const IpcParseError& e) {
    return head("", false) +
           std::format(R"(,"error":{{"code":"{}","message":{}}}}})", to_string(e.code), q(ipc_error_message(e.code))) +
           "\n";
}

// --- client side ----------------------------------------------------------------------------

namespace {

struct Reader {
    std::string err;
    bool fail(const char* m) {
        if (err.empty()) err = m;
        return false;
    }
    bool str(const JsonValue& o, const char* key, std::string& out, bool allow_null = false) {
        const JsonValue* v = o.find(key);
        if (!v) return fail("missing field");
        if (allow_null && v->type == JsonValue::Type::Null) {
            out.clear();
            return true;
        }
        if (v->type != JsonValue::Type::String) return fail("field has the wrong type");
        if (v->string.size() > kIpcMaxStringField) return fail("string field too long");
        out = v->string;
        return true;
    }
    bool integer(const JsonValue& o, const char* key, long long& out, long long lo, long long hi) {
        const JsonValue* v = o.find(key);
        if (!v) return fail("missing field");
        if (v->type != JsonValue::Type::Number || !v->is_integer) return fail("field has the wrong type");
        if (v->integer < lo || v->integer > hi) return fail("number out of range");
        out = v->integer;
        return true;
    }
    bool boolean(const JsonValue& o, const char* key, bool& out) {
        const JsonValue* v = o.find(key);
        if (!v) return fail("missing field");
        if (v->type != JsonValue::Type::Bool) return fail("field has the wrong type");
        out = v->boolean;
        return true;
    }
};

constexpr long long kMaxCounter = 1'000'000'000'000LL;

bool parse_state(const std::string& s, ObserverState& out) {
    for (ObserverState st : {ObserverState::Starting, ObserverState::Running, ObserverState::Stopping, ObserverState::Stopped})
        if (s == to_string(st)) {
            out = st;
            return true;
        }
    return false;
}

bool parse_overall(const JsonValue& o, std::optional<Overall>& out, Reader& rd) {
    const JsonValue* v = o.find("overall");
    if (!v) return rd.fail("missing field");
    if (v->type == JsonValue::Type::Null) {
        out.reset();
        return true;
    }
    if (v->type != JsonValue::Type::String) return rd.fail("field has the wrong type");
    for (Overall x : {Overall::Observed, Overall::ObservedWithIssues, Overall::Incomplete})
        if (v->string == to_string(x)) {
            out = x;
            return true;
        }
    return rd.fail("unknown overall value");
}

bool parse_status(const JsonValue& d, ObserverStatus& s, Reader& rd) {
    std::string state;
    if (!rd.str(d, "state", state) || !rd.str(d, "started_utc", s.started_utc) ||
        !rd.str(d, "last_observation_utc", s.last_observation_utc) || !rd.str(d, "last_error", s.last_error) ||
        !rd.str(d, "version", s.version))
        return false;
    if (!parse_state(state, s.state)) return rd.fail("unknown state");
    return rd.integer(d, "polls", s.polls, 0, kMaxCounter) && rd.integer(d, "events_total", s.events_total, 0, kMaxCounter) &&
           rd.integer(d, "store_errors", s.store_errors, 0, kMaxCounter) &&
           rd.integer(d, "snapshot_errors", s.snapshot_errors, 0, kMaxCounter) && parse_overall(d, s.overall, rd);
}

bool parse_event(const JsonValue& o, StoredEvent& e, Reader& rd) {
    if (o.type != JsonValue::Type::Object) return rd.fail("event is not an object");
    long long id = 0, conf = 0;
    if (!rd.integer(o, "id", id, 0, kMaxCounter) || !rd.str(o, "kind", e.kind) ||
        !rd.str(o, "observed_at_utc", e.observed_at_utc) ||
        !rd.str(o, "first_observed_at_utc", e.first_observed_at_utc) || !rd.str(o, "check_id", e.check_id) ||
        !rd.str(o, "from", e.from_state, true) || !rd.str(o, "to", e.to_state, true) ||
        !rd.integer(o, "confirmations", conf, 0, 1000000) || !rd.str(o, "source", e.source) ||
        !rd.str(o, "error_code", e.error_code) || !rd.boolean(o, "evidence_valid", e.evidence_valid))
        return false;
    e.id = id;
    e.confirmations = static_cast<int>(conf);
    const JsonValue* ev = o.find("evidence");
    if (!ev || ev->type != JsonValue::Type::Object) return rd.fail("evidence is not an object");
    if (ev->object.size() > kStoreMaxEvidencePairs) return rd.fail("too many evidence pairs");
    for (const auto& [k, v] : ev->object) {
        if (v.type != JsonValue::Type::String || k.size() > kIpcMaxStringField || v.string.size() > kIpcMaxStringField)
            return rd.fail("evidence value is not a short string");
        e.evidence.emplace_back(k, v.string);
    }
    return true;
}

}  // namespace

IpcParsedResponse parse_response(std::string_view line, IpcVerb expected) {
    IpcParsedResponse out;
    auto bad = [&](const std::string& why) {
        out.valid = false;
        out.error = why;
        out.response = {};
        return out;
    };
    if (line.empty()) return bad("empty reply");
    if (line.size() > kIpcMaxResponseBytes) return bad("reply is too large");
    if (line.back() == '\n') line.remove_suffix(1);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.find('\n') != std::string_view::npos) return bad("reply is not a single line");

    const JsonParseResult pr = json_parse(line, 8);
    if (!pr.ok) return bad("reply is not valid JSON: " + pr.error);
    const JsonValue& root = pr.value;
    if (root.type != JsonValue::Type::Object) return bad("reply is not a JSON object");

    Reader rd;
    long long schema = 0;
    std::string command, request;
    bool ok = false;
    if (!rd.integer(root, "schema_version", schema, 0, 1000) || schema != kSchemaVersion)
        return bad("unsupported reply schema");
    if (!rd.str(root, "command", command) || command != "service-ipc") return bad("reply is not a service-ipc reply");
    if (!rd.str(root, "request", request) || !rd.boolean(root, "ok", ok)) return bad("reply is missing fields");

    IpcResponse r;
    r.verb = expected;
    r.ok = ok;
    if (!ok) {
        const JsonValue* e = root.find("error");
        if (!e || e->type != JsonValue::Type::Object) return bad("reply has no error object");
        std::string code;
        if (!rd.str(*e, "code", code) || !rd.str(*e, "message", r.error_message)) return bad("malformed error object");
        r.error_code = ipc_error_from_string(code).value_or(IpcErrorCode::Internal);
        out.valid = true;
        out.response = std::move(r);
        return out;
    }
    if (request != to_string(expected)) return bad("reply answers a different request");
    const JsonValue* d = root.find("data");
    if (!d || d->type != JsonValue::Type::Object) return bad("reply has no data object");
    switch (expected) {
        case IpcVerb::Status: {
            ObserverStatus s;
            if (!parse_status(*d, s, rd)) return bad("malformed status: " + rd.err);
            r.status = std::move(s);
            break;
        }
        case IpcVerb::Health: {
            IpcHealth h;
            if (!rd.str(*d, "health", h.health) || !rd.str(*d, "state", h.state) ||
                !rd.integer(*d, "store_errors", h.store_errors, 0, kMaxCounter) ||
                !rd.integer(*d, "snapshot_errors", h.snapshot_errors, 0, kMaxCounter))
                return bad("malformed health: " + rd.err);
            r.health = std::move(h);
            break;
        }
        case IpcVerb::Events: {
            IpcEventsData ed;
            long long limit = 0, count = 0;
            if (!rd.integer(*d, "limit", limit, 1, kIpcMaxEvents) || !rd.integer(*d, "count", count, 0, kIpcMaxEvents) ||
                !rd.boolean(*d, "truncated", ed.truncated))
                return bad("malformed events: " + rd.err);
            ed.limit = static_cast<int>(limit);
            const JsonValue* arr = d->find("events");
            if (!arr || arr->type != JsonValue::Type::Array) return bad("malformed events: events is not an array");
            if (arr->array.size() > static_cast<std::size_t>(kIpcMaxEvents) ||
                arr->array.size() != static_cast<std::size_t>(count))
                return bad("malformed events: count does not match");
            for (const auto& item : arr->array) {
                StoredEvent e;
                if (!parse_event(item, e, rd)) return bad("malformed event: " + rd.err);
                ed.events.push_back(std::move(e));
            }
            r.events = std::move(ed);
            break;
        }
    }
    out.valid = true;
    out.response = std::move(r);
    return out;
}

}  // namespace metasec
