// Tests for the pure half of MVP-4: JSON parser, IPC line protocol, service status model,
// `service ...` argument parsing and the generalised approval. No OS, no pipe, no files.
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/cli.hpp"
#include "core/ipc_proto.hpp"
#include "core/json.hpp"
#include "core/scan.hpp"
#include "core/service_model.hpp"

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

bool contains(const std::string& s, std::string_view needle) { return s.find(needle) != std::string::npos; }
std::size_t count_char(const std::string& s, char c) {
    std::size_t n = 0;
    for (char x : s) n += x == c;
    return n;
}

// ---- JSON parser ----------------------------------------------------------------------------
void test_json_parser() {
    const char* good[] = {"{}", "[]", "null", "true", "false", "0", "-0", "12", "-3.5e+2", "\"\"", "\"a\\n\\u00e9\\ud83d\\ude00\"",
                          " { \"a\" : [ 1 , 2 , { \"b\" : null } ] } ", "\"\xC3\xA9\""};
    for (const char* g : good) CHECK(json_parse(g).ok);
    const char* bad[] = {"",           "{",          "}",         "[1,]",       "{\"a\":1,}", "{\"a\" 1}",   "{a:1}",
                         "'a'",        "01",         "1.",        ".5",         "+1",         "1e",          "nul",
                         "True",       "\"abc",      "\"a\nb\"",  "\"\\x\"",    "\"\\u12\"",  "\"\\ud800\"", "\"\\udc00\"",
                         "\"\xC3\"",   "\"\xFF\"",   "{} {}",     "[1] x",      "{\"a\":1,\"a\":2}", "// c\n1", "[1 2]",
                         "\"\\ud83d\\u0041\""};
    for (const char* b : bad) CHECK(!json_parse(b).ok);
    CHECK(!json_parse(std::string("\"a\0b\"", 5)).ok);  // NUL is a control character

    const JsonParseResult r = json_parse(R"({"s":"x\u00e9\n","n":42,"f":1.5,"b":true,"z":null,"a":[1,2],"o":{"k":"v"}})");
    CHECK(r.ok);
    CHECK(r.value.find("s") && r.value.find("s")->string == "x\xC3\xA9\n");
    CHECK(r.value.find("n") && r.value.find("n")->is_integer && r.value.find("n")->integer == 42);
    CHECK(r.value.find("f") && !r.value.find("f")->is_integer && r.value.find("f")->number == 1.5);
    CHECK(r.value.find("b") && r.value.find("b")->boolean);
    CHECK(r.value.find("z") && r.value.find("z")->type == JsonValue::Type::Null);
    CHECK(r.value.find("a") && r.value.find("a")->array.size() == 2);
    CHECK(r.value.find("o") && r.value.find("o")->find("k")->string == "v");
    CHECK(r.value.find("missing") == nullptr);
    // Depth limit
    std::string deep(40, '[');
    deep += std::string(40, ']');
    CHECK(!json_parse(deep, 16).ok);
    CHECK(json_parse(deep, 64).ok);
    // Huge integers are not claimed to be exact integers
    const JsonParseResult big = json_parse("123456789012345678901234567890");
    CHECK(big.ok && !big.value.is_integer);
    // escape/parse round trip on hostile text
    const std::string hostile = "q\"uote\\ back\n nl \x01 ctl \xC3\xA9 \xE2\x82\xAC";
    const JsonParseResult rt = json_parse("\"" + json_escape(hostile) + "\"");
    CHECK(rt.ok && rt.value.string == hostile);
}

// ---- IPC requests ---------------------------------------------------------------------------
void test_ipc_allowlist() {
    const auto& v = ipc_allowed_verbs();
    CHECK(v.size() == 3);
    CHECK(std::string(v[0]) == "STATUS");
    CHECK(std::string(v[1]) == "HEALTH");
    CHECK(std::string(v[2]) == "EVENTS");
    // Every verb outside the list is refused as UNKNOWN_COMMAND, including all that would write.
    const char* nope[] = {"SCAN", "POLICY", "SET", "FIX", "INSTALL", "UNINSTALL", "STOP", "START", "EXEC", "SHUTDOWN",
                          "DELETE", "WRITE", "CONFIG", "HELP", "PING", "QUIT", "SHELL", "PURGE", "CLEAR", "ENROLL",
                          "status", "health", "events", "Status", "StAtUs", "EVENT", "STATUSES", "EVENTS2", ""};
    for (const char* n : nope) {
        const auto r = parse_request(std::string(n) + "\n");
        if (std::string(n).empty()) {
            CHECK(std::holds_alternative<IpcParseError>(r));
            continue;
        }
        CHECK(std::holds_alternative<IpcParseError>(r));
        if (const auto* e = std::get_if<IpcParseError>(&r)) CHECK(e->code == IpcErrorCode::UnknownCommand);
    }
    CHECK(std::string(to_string(IpcVerb::Status)) == "STATUS");
}

void test_ipc_request_accept() {
    struct Case { const char* line; IpcVerb verb; int limit; };
    const Case ok[] = {{"STATUS\n", IpcVerb::Status, 0},     {"STATUS\r\n", IpcVerb::Status, 0},
                       {"HEALTH\n", IpcVerb::Health, 0},     {"HEALTH\r\n", IpcVerb::Health, 0},
                       {"EVENTS\n", IpcVerb::Events, 50},    {"EVENTS 1\n", IpcVerb::Events, 1},
                       {"EVENTS 9\n", IpcVerb::Events, 9},   {"EVENTS 20\r\n", IpcVerb::Events, 20},
                       {"EVENTS 200\n", IpcVerb::Events, 200}, {"EVENTS 199\n", IpcVerb::Events, 199}};
    for (const auto& c : ok) {
        const auto r = parse_request(c.line);
        const auto* req = std::get_if<IpcRequest>(&r);
        CHECK(req != nullptr);
        if (req) {
            CHECK(req->verb == c.verb);
            CHECK(req->limit == c.limit);
        }
    }
    CHECK(render_request({IpcVerb::Status, 0}) == "STATUS\n");
    CHECK(render_request({IpcVerb::Events, 0}) == "EVENTS\n");
    CHECK(render_request({IpcVerb::Events, 25}) == "EVENTS 25\n");
    // what the client renders, the server accepts
    for (const IpcRequest& q : {IpcRequest{IpcVerb::Health, 0}, IpcRequest{IpcVerb::Events, 7}})
        CHECK(std::holds_alternative<IpcRequest>(parse_request(render_request(q))));
}

void test_ipc_request_reject() {
    struct Case { std::string line; IpcErrorCode code; };
    const std::vector<Case> bad = {
        {"", IpcErrorCode::EmptyRequest},
        {"\n", IpcErrorCode::EmptyRequest},
        {"\r\n", IpcErrorCode::EmptyRequest},
        {"STATUS", IpcErrorCode::NoNewline},
        {"EVENTS 5", IpcErrorCode::NoNewline},
        {"STATUS\r", IpcErrorCode::NoNewline},
        {"STATUS\n\n", IpcErrorCode::ControlCharacter},
        {"STATUS\nHEALTH\n", IpcErrorCode::ControlCharacter},
        {"STATUS\r\r\n", IpcErrorCode::ControlCharacter},
        {std::string("STATUS\0\n", 8), IpcErrorCode::EmbeddedNul},
        {std::string("\0", 1), IpcErrorCode::EmbeddedNul},
        {"STATUS\t\n", IpcErrorCode::ControlCharacter},
        {"STAT\x01US\n", IpcErrorCode::ControlCharacter},
        {"STATUS\x1b[31m\n", IpcErrorCode::ControlCharacter},
        {"STATUS\x7f\n", IpcErrorCode::ControlCharacter},
        {"STATUS\xC3\xA9\n", IpcErrorCode::NonAscii},
        {"STATUS\xFF\n", IpcErrorCode::NonAscii},
        {"\xEF\xBB\xBFSTATUS\n", IpcErrorCode::NonAscii},
        {"STATUS \n", IpcErrorCode::ExtraTokens},
        {" STATUS\n", IpcErrorCode::ExtraTokens},
        {"STATUS  \n", IpcErrorCode::ExtraTokens},
        {"STATUS now\n", IpcErrorCode::ExtraTokens},
        {"HEALTH 1\n", IpcErrorCode::ExtraTokens},
        {"EVENTS 1 2\n", IpcErrorCode::ExtraTokens},
        {"EVENTS  5\n", IpcErrorCode::ExtraTokens},
        {"EVENTS 5 \n", IpcErrorCode::ExtraTokens},
        {"EVENTS 0\n", IpcErrorCode::BadArgument},
        {"EVENTS 201\n", IpcErrorCode::BadArgument},
        {"EVENTS 1000\n", IpcErrorCode::BadArgument},
        {"EVENTS 05\n", IpcErrorCode::BadArgument},
        {"EVENTS 00\n", IpcErrorCode::BadArgument},
        {"EVENTS -1\n", IpcErrorCode::BadArgument},
        {"EVENTS +5\n", IpcErrorCode::BadArgument},
        {"EVENTS 5x\n", IpcErrorCode::BadArgument},
        {"EVENTS abc\n", IpcErrorCode::BadArgument},
        {"EVENTS 1e2\n", IpcErrorCode::BadArgument},
        {"EVENTS 0x10\n", IpcErrorCode::BadArgument},
        {"EVENTS 5.0\n", IpcErrorCode::BadArgument},
        {"EVENTS 99999999999999999999\n", IpcErrorCode::BadArgument},
        {"status\n", IpcErrorCode::UnknownCommand},
        {"Events 5\n", IpcErrorCode::UnknownCommand},
        {"SHUTDOWN\n", IpcErrorCode::UnknownCommand},
        {"STATUS;SCAN\n", IpcErrorCode::UnknownCommand},
        {"STATUS&&dir\n", IpcErrorCode::UnknownCommand},
        {std::string(128, 'A') + "", IpcErrorCode::NoNewline},  // 128 bytes, no terminator
        {std::string(127, 'A') + "\n", IpcErrorCode::UnknownCommand},  // exactly 128 bytes: within the limit
        {std::string(129, 'A'), IpcErrorCode::RequestTooLong},
        {std::string(129, 'A') + "\n", IpcErrorCode::RequestTooLong},
        {std::string(100000, 'A'), IpcErrorCode::RequestTooLong},
        {"EVENTS " + std::string(200, '1') + "\n", IpcErrorCode::RequestTooLong},
    };
    for (const auto& c : bad) {
        const auto r = parse_request(c.line);
        const auto* e = std::get_if<IpcParseError>(&r);
        CHECK(e != nullptr);
        if (!e) continue;
        CHECK(e->code == c.code);
        if (e->code != c.code)
            std::fprintf(stderr, "  input (%zu bytes) gave %s, wanted %s\n", c.line.size(), to_string(e->code), to_string(c.code));
        CHECK(e->message == ipc_error_message(e->code));
    }
}

void test_ipc_errors_never_echo_input() {
    const std::string marker = "EVIL_PAYLOAD_9f3a";
    const std::vector<std::string> inputs = {marker + "\n", "STATUS " + marker + "\n", "EVENTS " + marker + "\n",
                                             marker, marker + "\x01\n", marker + "\xC3\xA9\n", "EVENTS " + marker + std::string(300, 'x')};
    for (const auto& in : inputs) {
        const auto r = parse_request(in);
        const auto* e = std::get_if<IpcParseError>(&r);
        CHECK(e != nullptr);
        if (!e) continue;
        CHECK(!contains(e->message, marker));
        const std::string line = render_ipc_parse_error(*e);
        CHECK(!contains(line, marker));
        CHECK(line.back() == '\n' && count_char(line, '\n') == 1);
        const JsonParseResult j = json_parse(line);
        CHECK(j.ok);
        if (j.ok) {
            CHECK(j.value.find("ok") && !j.value.find("ok")->boolean);
            CHECK(j.value.find("command") && j.value.find("command")->string == "service-ipc");
            CHECK(j.value.find("request") && j.value.find("request")->string.empty());
            const JsonValue* err = j.value.find("error");
            CHECK(err && err->find("code") && ipc_error_from_string(err->find("code")->string).has_value());
        }
    }
    // every code has a stable string that parses back
    for (IpcErrorCode c : {IpcErrorCode::EmptyRequest, IpcErrorCode::RequestTooLong, IpcErrorCode::NoNewline,
                           IpcErrorCode::EmbeddedNul, IpcErrorCode::NonAscii, IpcErrorCode::ControlCharacter,
                           IpcErrorCode::UnknownCommand, IpcErrorCode::ExtraTokens, IpcErrorCode::BadArgument,
                           IpcErrorCode::StoreUnavailable, IpcErrorCode::Internal})
        CHECK(ipc_error_from_string(to_string(c)) == c);
    CHECK(!ipc_error_from_string("NOPE").has_value());
}

// ---- IPC responses --------------------------------------------------------------------------
ObserverStatus sample_status() {
    ObserverStatus s;
    s.state = ObserverState::Running;
    s.started_utc = "2026-10-30T00:00:00Z";
    s.last_observation_utc = "2026-10-30T00:05:00Z";
    s.polls = 10;
    s.events_total = 3;
    s.store_errors = 0;
    s.snapshot_errors = 0;
    s.overall = Overall::ObservedWithIssues;
    s.version = "0.1.0";
    return s;
}

StoredEvent sample_event(int id, std::size_t evidence_len = 8, int pairs = 2) {
    StoredEvent e;
    e.id = id;
    e.kind = "change";
    e.observed_at_utc = "2026-10-30T00:00:10Z";
    e.first_observed_at_utc = "2026-10-30T00:00:00Z";
    e.check_id = "firewall.public";
    e.from_state = "ENABLED";
    e.to_state = "DISABLED";
    e.confirmations = 2;
    e.source = "INetFwPolicy2";
    for (int p = 0; p < pairs; ++p) e.evidence.emplace_back("k" + std::to_string(p), std::string(evidence_len, 'v'));
    return e;
}

void test_ipc_status_roundtrip() {
    ObserverStatus s = sample_status();
    s.last_error = "line1\nline2 \"quoted\" \\ \x01 \xC3\xA9";
    s.store_errors = 2;
    const std::string line = render_ipc_status(s);
    CHECK(line.back() == '\n' && count_char(line, '\n') == 1);
    CHECK(line.size() <= kIpcMaxResponseBytes);
    const IpcParsedResponse p = parse_response(line, IpcVerb::Status);
    CHECK(p.valid);
    CHECK(p.response.ok);
    CHECK(p.response.status.has_value());
    if (p.response.status) {
        const ObserverStatus& g = *p.response.status;
        CHECK(g.state == ObserverState::Running);
        CHECK(g.started_utc == s.started_utc);
        CHECK(g.last_observation_utc == s.last_observation_utc);
        CHECK(g.polls == 10 && g.events_total == 3 && g.store_errors == 2 && g.snapshot_errors == 0);
        CHECK(g.last_error == s.last_error);
        CHECK(g.overall && *g.overall == Overall::ObservedWithIssues);
        CHECK(g.version == "0.1.0");
    }
    // overall absent before the first poll
    ObserverStatus fresh;
    fresh.state = ObserverState::Starting;
    const IpcParsedResponse pf = parse_response(render_ipc_status(fresh), IpcVerb::Status);
    CHECK(pf.valid && pf.response.status && !pf.response.status->overall.has_value());
    // asking for a different verb than the reply answers is rejected
    CHECK(!parse_response(line, IpcVerb::Health).valid);
    CHECK(!parse_response(line, IpcVerb::Events).valid);
}

void test_ipc_health() {
    ObserverStatus s = sample_status();
    CHECK(std::string(health_of(s)) == "OK");
    s.store_errors = 1;
    CHECK(std::string(health_of(s)) == "DEGRADED");
    s.store_errors = 0;
    s.snapshot_errors = 1;
    CHECK(std::string(health_of(s)) == "DEGRADED");
    s.snapshot_errors = 0;
    s.polls = 0;
    CHECK(std::string(health_of(s)) == "DEGRADED");
    s.state = ObserverState::Starting;
    CHECK(std::string(health_of(s)) == "STARTING");
    s.state = ObserverState::Stopping;
    CHECK(std::string(health_of(s)) == "STOPPING");
    s.state = ObserverState::Stopped;
    CHECK(std::string(health_of(s)) == "STOPPED");
    const IpcParsedResponse p = parse_response(render_ipc_health(sample_status()), IpcVerb::Health);
    CHECK(p.valid && p.response.health.has_value());
    if (p.response.health) {
        CHECK(p.response.health->health == "OK");
        CHECK(p.response.health->state == "running");
    }
}

void test_ipc_events_roundtrip_and_truncation() {
    std::vector<StoredEvent> few = {sample_event(3), sample_event(2), sample_event(1)};
    few[0].evidence.emplace_back("hostile", "a\"b\\c\nd\x01 \xC3\xA9");
    few[1].from_state.clear();  // added check: from is null
    const std::string line = render_ipc_events(few, 50);
    CHECK(line.back() == '\n' && count_char(line, '\n') == 1);
    const IpcParsedResponse p = parse_response(line, IpcVerb::Events);
    CHECK(p.valid && p.response.events.has_value());
    if (p.response.events) {
        const IpcEventsData& d = *p.response.events;
        CHECK(d.limit == 50);
        CHECK(!d.truncated);
        CHECK(d.events.size() == 3);
        if (d.events.size() == 3) {
            CHECK(d.events[0].id == 3);
            CHECK(d.events[0].evidence.size() == 3);
            CHECK(d.events[0].evidence[2].second == "a\"b\\c\nd\x01 \xC3\xA9");
            CHECK(d.events[1].from_state.empty());
            CHECK(d.events[2].id == 1);
            CHECK(d.events[0].to_state == "DISABLED");
        }
    }
    // limit is honoured and clamped
    CHECK(parse_response(render_ipc_events(few, 2), IpcVerb::Events).response.events->events.size() == 2);
    CHECK(parse_response(render_ipc_events(few, 0), IpcVerb::Events).response.events->limit == 1);
    CHECK(parse_response(render_ipc_events({}, 10), IpcVerb::Events).response.events->events.empty());

    // Oversize: 200 fat events cannot fit in 256 KiB. Oldest (last) are dropped, truncated is set.
    std::vector<StoredEvent> fat;
    for (int i = 200; i >= 1; --i) fat.push_back(sample_event(i, 256, 16));
    const std::string big = render_ipc_events(fat, 200);
    CHECK(big.size() <= kIpcMaxResponseBytes);
    CHECK(count_char(big, '\n') == 1);
    const IpcParsedResponse pb = parse_response(big, IpcVerb::Events);
    CHECK(pb.valid && pb.response.events.has_value());
    if (pb.response.events) {
        CHECK(pb.response.events->truncated);
        CHECK(!pb.response.events->events.empty());
        CHECK(pb.response.events->events.size() < 200);
        CHECK(pb.response.events->events.front().id == 200);  // newest kept
        CHECK(pb.response.events->events.back().id > 1);       // oldest dropped
    }
}

void test_ipc_error_reply() {
    const std::string line = render_ipc_error(IpcVerb::Events, IpcErrorCode::StoreUnavailable);
    const IpcParsedResponse p = parse_response(line, IpcVerb::Events);
    CHECK(p.valid);
    CHECK(!p.response.ok);
    CHECK(p.response.error_code == IpcErrorCode::StoreUnavailable);
    CHECK(!p.response.error_message.empty());
    // a newer server may send a code we do not know: still a valid refusal, mapped to INTERNAL
    const IpcParsedResponse u = parse_response(
        R"({"schema_version":1,"command":"service-ipc","request":"STATUS","ok":false,"error":{"code":"FUTURE","message":"m"}})", IpcVerb::Status);
    CHECK(u.valid && !u.response.ok && u.response.error_code == IpcErrorCode::Internal);
}

void test_parse_response_strictness() {
    const std::string good = render_ipc_status(sample_status());
    CHECK(parse_response(good, IpcVerb::Status).valid);
    CHECK(parse_response(good.substr(0, good.size() - 1), IpcVerb::Status).valid);  // newline is optional
    const std::string base = good.substr(0, good.size() - 1);
    auto replace = [&](std::string from, std::string to) {
        std::string s = base;
        const auto at = s.find(from);
        if (at == std::string::npos) return std::string("<<missing>>");
        s.replace(at, from.size(), to);
        return s;
    };
    const std::vector<std::string> bad = {
        "",
        "\n",
        "not json",
        "[]",
        "{}",
        base + "x",
        base + "\n" + base,
        base + " " + base,
        replace("\"schema_version\":1", "\"schema_version\":2"),
        replace("\"schema_version\":1", "\"schema_version\":\"1\""),
        replace("\"command\":\"service-ipc\"", "\"command\":\"watch\""),
        replace("\"ok\":true", "\"ok\":1"),
        replace("\"state\":\"running\"", "\"state\":\"exploding\""),
        replace("\"polls\":10", "\"polls\":-1"),
        replace("\"polls\":10", "\"polls\":1.5"),
        replace("\"polls\":10", "\"polls\":\"10\""),
        replace("\"polls\":10", "\"polls\":99999999999999999"),
        replace("\"overall\":\"OBSERVED_WITH_ISSUES\"", "\"overall\":\"FINE\""),
        replace("\"overall\":\"OBSERVED_WITH_ISSUES\"", "\"overall\":5"),
        replace("\"version\":\"0.1.0\"", "\"version\":\"" + std::string(2000, 'v') + "\""),
        replace("\"data\":{", "\"dat\":{"),
        replace("\"data\":{", "\"data\":{\"polls\":1,"),  // duplicate key
        std::string(kIpcMaxResponseBytes + 1, ' '),
    };
    for (const auto& b : bad) {
        const IpcParsedResponse r = parse_response(b, IpcVerb::Status);
        CHECK(!r.valid);
        CHECK(!r.response.status.has_value());
        CHECK(!r.error.empty());
    }
    // event counts must agree with the array
    const std::string ev = render_ipc_events({sample_event(1)}, 5);
    std::string liar = ev;
    liar.replace(liar.find("\"count\":1"), 9, "\"count\":2");
    CHECK(!parse_response(liar, IpcVerb::Events).valid);
    std::string wrong_type = ev;
    wrong_type.replace(wrong_type.find("\"confirmations\":2"), 16, "\"confirmations\":\"2\"");
    CHECK(!parse_response(wrong_type, IpcVerb::Events).valid);
    std::string evidence_obj = ev;
    evidence_obj.replace(evidence_obj.find("\"k0\":\"vvvvvvvv\""), 15, "\"k0\":5");
    CHECK(!parse_response(evidence_obj, IpcVerb::Events).valid);
    // exactly the size limit is fine, one more byte is not
    CHECK(parse_response(good, IpcVerb::Status).valid);
}

// ---- service model --------------------------------------------------------------------------
ServiceInfo installed(RunState run) {
    ServiceInfo s;
    s.install = InstallState::Installed;
    s.run = run;
    s.start_type = StartType::Auto;
    s.account = "LocalSystem";
    s.binary_path = "\"C:\\Program Files\\META\\meta-sec.exe\" service run --scm";
    s.binary_matches_cli = true;
    return s;
}

IpcSnapshot ipc_ok(ObserverStatus st = sample_status()) {
    IpcSnapshot i;
    i.reach = IpcReach::Ok;
    i.status = std::move(st);
    return i;
}

void test_service_verdicts() {
    const std::string t = "2026-10-30T01:02:03Z";
    {  // not installed: a valid observation, exit 0, plain message
        ServiceInfo s;
        const auto r = build_service_status_report(t, s, {});
        CHECK(r.verdict == ServiceVerdict::NotInstalled);
        CHECK(r.overall == Overall::Observed);
        CHECK(r.exit_code == 0);
        CHECK(contains(r.message, "service is not installed; standalone commands (status/audit/watch/scan) work without it"));
    }
    {  // installed but stopped
        const auto r = build_service_status_report(t, installed(RunState::Stopped), {});
        CHECK(r.verdict == ServiceVerdict::Stopped);
        CHECK(r.exit_code == 0);
        CHECK(r.overall == Overall::Observed);
        CHECK(contains(r.message, "installed but not running"));
        ServiceInfo d = installed(RunState::Stopped);
        d.start_type = StartType::Disabled;
        CHECK(contains(build_service_status_report(t, d, {}).message, "DISABLED"));
    }
    {  // running and healthy
        const auto r = build_service_status_report(t, installed(RunState::Running), ipc_ok());
        CHECK(r.verdict == ServiceVerdict::Running);
        CHECK(r.exit_code == 0);
        CHECK(r.overall == Overall::Observed);
    }
    {  // running with store errors: reported, still exit 0 (observed with issues)
        ObserverStatus st = sample_status();
        st.store_errors = 3;
        st.last_error = "event store is full";
        const auto r = build_service_status_report(t, installed(RunState::Running), ipc_ok(st));
        CHECK(r.verdict == ServiceVerdict::RunningWithIssues);
        CHECK(r.overall == Overall::ObservedWithIssues);
        CHECK(r.exit_code == 0);
        CHECK(contains(r.message, "3 store error"));
        CHECK(contains(r.message, "event store is full"));
    }
    {  // running but the pipe is unreachable / denied / garbage: exit 3 with the reason
        for (IpcReach reach : {IpcReach::Unreachable, IpcReach::AccessDenied, IpcReach::InvalidReply, IpcReach::NotTried}) {
            IpcSnapshot i;
            i.reach = reach;
            i.reason = "pipe said no";
            const auto r = build_service_status_report(t, installed(RunState::Running), i);
            CHECK(r.verdict == ServiceVerdict::IpcUnavailable);
            CHECK(r.overall == Overall::Incomplete);
            CHECK(r.exit_code == 3);
            if (reach != IpcReach::NotTried) CHECK(contains(r.message, "pipe said no"));
            CHECK(contains(r.message, to_string(reach)) || reach == IpcReach::NotTried);
        }
        // Ok without data is not trusted
        IpcSnapshot odd;
        odd.reach = IpcReach::Ok;
        CHECK(build_service_status_report(t, installed(RunState::Running), odd).exit_code == 3);
    }
    {  // SCM query failed: exit 3, never "not installed", never exit 2
        ServiceInfo s;
        s.query_ok = false;
        s.query_error = "ACCESS_DENIED";
        const auto r = build_service_status_report(t, s, {});
        CHECK(r.verdict == ServiceVerdict::QueryFailed);
        CHECK(r.exit_code == 3);
        CHECK(contains(r.message, "ACCESS_DENIED"));
        CHECK(!contains(r.message, "not installed"));
    }
    for (RunState rs : {RunState::StartPending, RunState::StopPending, RunState::ContinuePending, RunState::PausePending}) {
        const auto r = build_service_status_report(t, installed(rs), {});
        CHECK(r.verdict == ServiceVerdict::Pending);
        CHECK(r.exit_code == 3);
    }
    for (RunState rs : {RunState::Paused, RunState::Unknown}) {
        const auto r = build_service_status_report(t, installed(rs), {});
        CHECK(r.verdict == ServiceVerdict::UnexpectedState);
        CHECK(r.exit_code == 3);
    }
}

void test_service_render() {
    const std::string t = "2026-10-30T01:02:03Z";
    const std::vector<ServiceStatusReport> reports = {
        build_service_status_report(t, ServiceInfo{}, {}),
        build_service_status_report(t, installed(RunState::Stopped), {}),
        build_service_status_report(t, installed(RunState::Running), ipc_ok()),
        build_service_status_report(t, installed(RunState::Running), IpcSnapshot{IpcReach::AccessDenied, "denied \"x\"\n", std::nullopt}),
        build_service_status_report(t, ServiceInfo{false, "WIN32:5", InstallState::NotInstalled, RunState::Unknown, StartType::Unknown, "", "", std::nullopt}, {}),
    };
    for (const auto& r : reports) {
        const std::string j = render_service_status_json(r, "0.1.0");
        CHECK(j.back() == '\n' && count_char(j, '\n') == 1);
        const JsonParseResult p = json_parse(j);
        CHECK(p.ok);
        if (!p.ok) continue;
        CHECK(p.value.find("schema_version") && p.value.find("schema_version")->integer == 1);
        CHECK(p.value.find("command") && p.value.find("command")->string == "service status");
        CHECK(p.value.find("overall") && p.value.find("overall")->string == to_string(r.overall));
        CHECK(p.value.find("verdict") && p.value.find("verdict")->string == to_string(r.verdict));
        CHECK(p.value.find("service") && p.value.find("service")->find("installed"));
        CHECK(p.value.find("ipc") && p.value.find("ipc")->find("reachable"));
        CHECK(p.value.find("message") && !p.value.find("message")->string.empty());
        const std::string text = render_service_status_text(r, "0.1.0");
        CHECK(contains(text, r.message));
        CHECK(contains(text, to_string(r.overall)));
    }
    // running + ipc: counters present in both renderings
    const std::string j = render_service_status_json(reports[2], "0.1.0");
    CHECK(contains(j, "\"events_total\":3"));
    CHECK(contains(j, "\"polls\":10"));
    CHECK(contains(j, "\"binary_matches_cli\":true"));
    const std::string text = render_service_status_text(reports[2], "0.1.0");
    CHECK(contains(text, "3 stored in total"));
    CHECK(contains(text, "this meta-sec.exe"));
}

void test_service_render_hostile_and_redaction() {
    ServiceInfo s = installed(RunState::Running);
    s.account = "evil\x1b[31m\nACCOUNT";
    s.binary_path = "C:\\Users\\Alice Smith\\AppData\\meta-sec.exe\x1b[2J\r\n";
    const auto r = build_service_status_report("t", s, IpcSnapshot{IpcReach::Unreachable, "x\x1b[0m\ny", std::nullopt});
    const std::string text = render_service_status_text(r, "0.1.0");
    CHECK(text.find('\x1b') == std::string::npos);
    CHECK(text.find('\r') == std::string::npos);
    CHECK(!contains(text, "Alice"));
    CHECK(contains(text, "<user>"));
    const std::string j = render_service_status_json(r, "0.1.0");
    CHECK(!contains(j, "Alice"));
    CHECK(json_parse(j).ok);
    CHECK(redact_binary_path("C:\\Users\\bob\\x.exe") == "C:\\Users\\<user>\\x.exe");
    CHECK(redact_binary_path("c:\\USERS\\Bob\\x.exe") == "c:\\USERS\\<user>\\x.exe");
    CHECK(redact_binary_path("C:\\Program Files\\META\\meta-sec.exe") == "C:\\Program Files\\META\\meta-sec.exe");
    CHECK(redact_binary_path("D:/Users/carol/a.exe") == "D:/Users/<user>/a.exe");
    CHECK(redact_binary_path(std::string(1000, 'a')).size() == kDataDirMaxLen + 3);
    CHECK(redact_binary_path("a\tb\nc") == "a?b?c");
    // not installed: no binary path is ever shown
    ServiceInfo none;
    none.binary_path = "C:\\Users\\Alice\\leftover.exe";
    CHECK(!contains(render_service_status_json(build_service_status_report("t", none, {}), "1"), "leftover"));
}

void test_service_events_render() {
    ServiceEventsReport r;
    r.observed_at_utc = "2026-10-30T01:02:03Z";
    r.reach = IpcReach::Ok;
    IpcEventsData d;
    d.limit = 50;
    StoredEvent e = sample_event(7);
    e.evidence.insert(e.evidence.begin(), {"detected_after_restart", "true"});
    StoredEvent life;
    life.id = 6;
    life.kind = kLifecycleStarted;
    life.observed_at_utc = "2026-10-30T00:00:00Z";
    life.source = "service";
    e.check_id = "firewall.\x1b[31mpublic";
    d.events = {e, life};
    r.data = d;
    CHECK(service_events_exit_code(r) == 0);
    const std::string j = render_service_events_json(r, "0.1.0");
    CHECK(count_char(j, '\n') == 1);
    const JsonParseResult p = json_parse(j);
    CHECK(p.ok);
    if (p.ok) {
        CHECK(p.value.find("command")->string == "service events");
        CHECK(p.value.find("count")->integer == 2);
        CHECK(p.value.find("events")->array.size() == 2);
        CHECK(p.value.find("overall")->string == "OBSERVED");
        CHECK(p.value.find("events")->array[1].find("from")->type == JsonValue::Type::Null);
    }
    const std::string text = render_service_events_text(r, "0.1.0");
    CHECK(text.find('\x1b') == std::string::npos);
    CHECK(contains(text, "[CHANGE]"));
    CHECK(contains(text, "ENABLED -> DISABLED"));
    CHECK(contains(text, "detected after service restart"));
    CHECK(contains(text, "[SERVICE STARTED]"));

    ServiceEventsReport down;
    down.reach = IpcReach::Unreachable;
    down.reason = "pipe not found";
    CHECK(service_events_exit_code(down) == 3);
    const JsonParseResult pd = json_parse(render_service_events_json(down, "0.1.0"));
    CHECK(pd.ok && pd.value.find("overall")->string == "INCOMPLETE" && pd.value.find("events")->array.empty());
    CHECK(contains(render_service_events_text(down, "0.1.0"), "pipe not found"));
    ServiceEventsReport empty;
    empty.reach = IpcReach::Ok;
    empty.data = IpcEventsData{};
    CHECK(contains(render_service_events_text(empty, "0.1.0"), "No events"));
}

// ---- CLI ------------------------------------------------------------------------------------
ParsedArgs parse(std::vector<std::string> v) {
    std::vector<std::string_view> sv(v.begin(), v.end());
    return parse_args(sv);
}

void test_cli_service_accept() {
    {
        const ParsedArgs p = parse({"service", "status"});
        CHECK(p.command == Command::Service && p.service == ServiceCommand::Status && !p.json);
    }
    {
        const ParsedArgs p = parse({"service", "status", "--json"});
        CHECK(p.command == Command::Service && p.service == ServiceCommand::Status && p.json);
    }
    {
        const ParsedArgs p = parse({"service", "events"});
        CHECK(p.command == Command::Service && p.service == ServiceCommand::Events && p.limit == 50 && !p.json);
    }
    {
        const ParsedArgs p = parse({"service", "events", "--json", "--limit", "200"});
        CHECK(p.command == Command::Service && p.json && p.limit == 200);
        CHECK(parse({"service", "events", "--limit", "1"}).limit == 1);
        CHECK(parse({"service", "events", "--limit", "7", "--json"}).limit == 7);
    }
    {
        const ParsedArgs p = parse({"service", "install"});
        CHECK(p.command == Command::Service && p.service == ServiceCommand::Install && !p.dry_run);
        CHECK(parse({"service", "install", "--dry-run"}).dry_run);
        CHECK(parse({"service", "uninstall"}).service == ServiceCommand::Uninstall);
        CHECK(parse({"service", "uninstall", "--dry-run"}).dry_run);
    }
    {
        const ParsedArgs p = parse({"service", "run", "--console"});
        CHECK(p.command == Command::Service && p.service == ServiceCommand::Run && p.console && !p.scm);
        CHECK(p.interval_seconds == 30 && p.confirm_polls == 2 && p.max_polls == 0);
        CHECK(p.data_dir.empty() && p.pipe_name.empty());
    }
    {
        const ParsedArgs p = parse({"service", "run", "--console", "--data-dir", "C:\\temp\\meta data", "--pipe-name",
                                    "metasec-test_1.x", "--interval", "5", "--confirm", "3", "--max-polls", "10"});
        CHECK(p.command == Command::Service && p.console);
        CHECK(p.data_dir == "C:\\temp\\meta data");
        CHECK(p.pipe_name == "metasec-test_1.x");
        CHECK(p.interval_seconds == 5 && p.confirm_polls == 3 && p.max_polls == 10);
    }
    {
        const ParsedArgs p = parse({"service", "run", "--scm"});
        CHECK(p.command == Command::Service && p.service == ServiceCommand::Run && p.scm && !p.console);
    }
    {  // dev option: point status/events at a console-run observer
        CHECK(parse({"service", "status", "--pipe-name", "dev1"}).pipe_name == "dev1");
        CHECK(parse({"service", "events", "--pipe-name", "dev1", "--limit", "3"}).pipe_name == "dev1");
    }
    CHECK(parse({"service", "run", "--console", "--data-dir", std::string(260, 'd')}).command == Command::Service);
    CHECK(parse({"service", "run", "--console", "--pipe-name", std::string(64, 'p')}).command == Command::Service);
}

void test_cli_service_reject() {
    const std::vector<std::vector<std::string>> bad = {
        {"service"},
        {"service", "frobnicate"},
        {"service", "STATUS"},
        {"service", "status", "--bogus"},
        {"service", "status", "extra"},
        {"service", "status", "--json", "--json"},
        {"service", "status", "--limit", "5"},
        {"service", "status", "--dry-run"},
        {"service", "events", "--limit"},
        {"service", "events", "--limit", "0"},
        {"service", "events", "--limit", "201"},
        {"service", "events", "--limit", "-1"},
        {"service", "events", "--limit", "+5"},
        {"service", "events", "--limit", "5x"},
        {"service", "events", "--limit", "99999999999"},
        {"service", "events", "--limit", "5", "--limit", "6"},
        {"service", "events", "--json", "--json"},
        {"service", "events", "--dry-run"},
        {"service", "install", "--json", "--json"},
        {"service", "install", "--dry-run", "--dry-run"},
        {"service", "install", "--yes"},
        {"service", "install", "--force"},
        {"service", "install", "--console"},
        {"service", "uninstall", "--limit", "5"},
        {"service", "uninstall", "extra"},
        {"service", "run"},
        {"service", "run", "--json"},
        {"service", "run", "--console", "--scm"},
        {"service", "run", "--console", "--console"},
        {"service", "run", "--scm", "--scm"},
        {"service", "run", "--scm", "--max-polls", "3"},
        {"service", "run", "--scm", "--data-dir", "C:\\x"},
        {"service", "run", "--scm", "--pipe-name", "x"},
        {"service", "run", "--scm", "--interval", "5"},
        {"service", "run", "--scm", "--confirm", "2"},
        {"service", "run", "--max-polls", "3"},
        {"service", "run", "--data-dir", "C:\\x"},
        {"service", "run", "--console", "--max-polls", "0"},
        {"service", "run", "--console", "--max-polls", "1000001"},
        {"service", "run", "--console", "--interval", "0"},
        {"service", "run", "--console", "--interval", "3601"},
        {"service", "run", "--console", "--confirm", "11"},
        {"service", "run", "--console", "--interval", "5", "--interval", "6"},
        {"service", "run", "--console", "--data-dir"},
        {"service", "run", "--console", "--data-dir", ""},
        {"service", "run", "--console", "--data-dir", "\\\\server\\share\\x"},   // UNC
        {"service", "run", "--console", "--data-dir", "\\\\.\\pipe\\x"},         // device
        {"service", "run", "--console", "--data-dir", "\\\\?\\C:\\x"},           // extended-length
        {"service", "run", "--console", "--data-dir", "..\\up"},                 // relative, climbs out
        {"service", "run", "--console", "--data-dir", "C:\\a\\..\\b"},
        {"service", "run", "--console", "--data-dir", "a/../b"},
        {"service", "run", "--console", "--data-dir", "/rooted"},
        {"service", "run", "--console", "--pipe-name", "."},
        {"service", "run", "--console", "--pipe-name", ".."},
        {"service", "status", "--pipe-name", ".."},
        {"service", "run", "--console", "--data-dir", "--pipe-name", "x"},
        {"service", "run", "--console", "--data-dir", std::string(261, 'd')},
        {"service", "run", "--console", "--data-dir", "bad\x01path"},
        {"service", "run", "--console", "--data-dir", "bad\npath"},
        {"service", "run", "--console", "--data-dir", "a", "--data-dir", "b"},
        {"service", "run", "--console", "--pipe-name", ""},
        {"service", "run", "--console", "--pipe-name", "a\\b"},
        {"service", "run", "--console", "--pipe-name", "\\\\.\\pipe\\x"},
        {"service", "run", "--console", "--pipe-name", "a b"},
        {"service", "run", "--console", "--pipe-name", "a/b"},
        {"service", "run", "--console", "--pipe-name", "caf\xC3\xA9"},
        {"service", "run", "--console", "--pipe-name", std::string(65, 'p')},
        {"service", "run", "--console", "--pipe-name", "a", "--pipe-name", "b"},
        {"service", "status", "--pipe-name", "bad name"},
    };
    for (const auto& b : bad) {
        const ParsedArgs p = parse(b);
        CHECK(p.command == Command::Invalid);
        CHECK(!p.error.empty());
        if (p.command != Command::Invalid) {
            std::string joined;
            for (const auto& a : b) joined += a + " ";
            std::fprintf(stderr, "  accepted: %s\n", joined.c_str());
        }
    }
}

void test_cli_service_errors_are_sanitized() {
    const ParsedArgs p = parse({"service", "status", "\x1b[31mEVIL\nline"});
    CHECK(p.command == Command::Invalid);
    CHECK(p.error.find('\x1b') == std::string::npos);
    CHECK(p.error.find('\n') == std::string::npos);
    const ParsedArgs q = parse({"service", "run", "--console", "--pipe-name", "x\x1b[2J\n"});
    CHECK(q.command == Command::Invalid);
    CHECK(q.error.find('\x1b') == std::string::npos);
    CHECK(q.error.find('\n') == std::string::npos);
    const ParsedArgs r = parse({"service", "nope\x01"});
    CHECK(r.error.find('\x01') == std::string::npos);
}

void test_cli_existing_unchanged_and_usage() {
    CHECK(parse({"status"}).command == Command::Status);
    CHECK(parse({"watch", "--interval", "5"}).interval_seconds == 5);
    CHECK(parse({"scan", "--quick"}).command == Command::Scan);
    CHECK(parse({"services"}).command == Command::Invalid);
    const std::string u = usage_text("1.2.3");
    CHECK(contains(u, "service status"));
    CHECK(contains(u, "service events"));
    CHECK(contains(u, "service install"));
    CHECK(contains(u, "service run --console"));
    CHECK(!contains(u, "--scm"));  // internal entry point is documented in CLI.md, not advertised
}

// ---- approval -------------------------------------------------------------------------------
void test_generalised_approval() {
    auto in = [](std::string line) {
        ApprovalInput a;
        a.input_is_console = true;
        a.output_is_console = true;
        a.read = ReadStatus::Ok;
        a.line = std::move(line);
        return a;
    };
    // the old entry point behaves as before
    CHECK(evaluate_approval(in("START QUICK SCAN\r\n")).approved);
    CHECK(!evaluate_approval(in("INSTALL SERVICE\r\n")).approved);
    CHECK(evaluate_approval(in("START QUICK SCAN\r\n"), kScanConfirmPhrase).approved);
    // new phrases
    CHECK(evaluate_approval(in("INSTALL SERVICE\r\n"), kServiceInstallPhrase).approved);
    CHECK(evaluate_approval(in("INSTALL SERVICE\n"), kServiceInstallPhrase).approved);
    CHECK(evaluate_approval(in("UNINSTALL SERVICE\r\n"), kServiceUninstallPhrase).approved);
    CHECK(!evaluate_approval(in("UNINSTALL SERVICE\r\n"), kServiceInstallPhrase).approved);
    CHECK(!evaluate_approval(in("INSTALL SERVICE\r\n"), kServiceUninstallPhrase).approved);
    CHECK(!evaluate_approval(in("START QUICK SCAN\r\n"), kServiceInstallPhrase).approved);
    CHECK(evaluate_approval(in("install service\r\n"), kServiceInstallPhrase).reason == "WRONG_CONFIRMATION");
    CHECK(evaluate_approval(in("INSTALL SERVICE"), kServiceInstallPhrase).reason == "WRONG_CONFIRMATION");  // no Enter
    CHECK(evaluate_approval(in("INSTALL SERVICE \r\n"), kServiceInstallPhrase).reason == "WRONG_CONFIRMATION");
    CHECK(evaluate_approval(in("yes\r\n"), kServiceInstallPhrase).reason == "WRONG_CONFIRMATION");
    // an empty phrase must never approve, even an empty line
    CHECK(!evaluate_approval(in("\r\n"), "").approved);
    CHECK(!evaluate_approval(in("\n"), std::string_view()).approved);
    // every refusal that does not depend on the text is unchanged
    ApprovalInput pipe = in("INSTALL SERVICE\r\n");
    pipe.input_is_console = false;
    CHECK(evaluate_approval(pipe, kServiceInstallPhrase).reason == "NOT_A_CONSOLE");
    ApprovalInput blind = in("INSTALL SERVICE\r\n");
    blind.output_is_console = false;
    CHECK(evaluate_approval(blind, kServiceInstallPhrase).reason == "NO_VISIBLE_PROMPT");
    ApprovalInput eof = in("INSTALL SERVICE\r\n");
    eof.read = ReadStatus::Eof;
    CHECK(evaluate_approval(eof, kServiceInstallPhrase).reason == "EOF");
    eof.read = ReadStatus::Error;
    CHECK(evaluate_approval(eof, kServiceInstallPhrase).reason == "READ_ERROR");
    eof.read = ReadStatus::Interrupted;
    CHECK(evaluate_approval(eof, kServiceInstallPhrase).reason == "INTERRUPTED");
    // prompts name the exact phrase and the actor, and strip control characters
    const std::string pi = service_approval_prompt_text(true, "DOMAIN\\al\x1b[31mice", false);
    CHECK(contains(pi, kServiceInstallPhrase));
    CHECK(contains(pi, "not elevated"));
    CHECK(pi.find('\x1b') == std::string::npos);
    const std::string pu = service_approval_prompt_text(false, "bob", true);
    CHECK(contains(pu, kServiceUninstallPhrase));
    CHECK(!contains(pu, "not elevated"));
}

}  // namespace

int main() {
    test_json_parser();
    test_ipc_allowlist();
    test_ipc_request_accept();
    test_ipc_request_reject();
    test_ipc_errors_never_echo_input();
    test_ipc_status_roundtrip();
    test_ipc_health();
    test_ipc_events_roundtrip_and_truncation();
    test_ipc_error_reply();
    test_parse_response_strictness();
    test_service_verdicts();
    test_service_render();
    test_service_render_hostile_and_redaction();
    test_service_events_render();
    test_cli_service_accept();
    test_cli_service_reject();
    test_cli_service_errors_are_sanitized();
    test_cli_existing_unchanged_and_usage();
    test_generalised_approval();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
