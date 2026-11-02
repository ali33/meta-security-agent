#pragma once
// MVP-4: the local, READ-ONLY line protocol between the CLI (client) and the service (server)
// over the named pipe. Pure: no pipe, no Windows header. The Windows half only moves bytes:
//
//   server: read at most kIpcMaxRequestBytes bytes up to and including the first '\n'
//           -> parse_request(bytes) -> answer with one of the render_ipc_* lines
//   client: write render_request(...) -> read one line of at most kIpcMaxResponseBytes
//           -> parse_response(line, expected_verb)
//
// Request: ONE line, ASCII, at most 128 bytes including the terminator "\n" (or "\r\n"):
//     STATUS | HEALTH | EVENTS [n]        (n = 1..200, decimal, no sign, no leading zero; default 50)
// The verb allowlist is exactly those three. There is no write, scan, policy or configuration verb,
// and none can be added without changing ipc_allowed_verbs() (a unit test pins the list).
// Anything else -- unknown or lowercase verb, extra tokens, double spaces, control characters,
// non-ASCII, empty line, NUL, missing newline within the limit, oversize -- is rejected with a typed
// IpcErrorCode. The offending input is NEVER echoed back (messages are fixed strings).
//
// Response: ONE line of JSON ending in "\n", at most kIpcMaxResponseBytes (256 KiB) including it:
//     {"schema_version":1,"command":"service-ipc","request":"STATUS","ok":true,"data":{...}}
//     {"schema_version":1,"command":"service-ipc","request":"STATUS","ok":false,
//      "error":{"code":"UNKNOWN_COMMAND","message":"..."}}
// ("request" is "" when the request itself was not understood.) EVENTS lists newest first; if the
// line would exceed the limit the OLDEST events are dropped first and "truncated":true is set.
// Clients must treat every string as untrusted data (sanitize before printing).
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "observer.hpp"
#include "store.hpp"

namespace metasec {

inline constexpr std::size_t kIpcMaxRequestBytes = 128;
inline constexpr std::size_t kIpcMaxResponseBytes = 256 * 1024;
inline constexpr int kIpcDefaultEvents = 50;
inline constexpr int kIpcMaxEvents = 200;
inline constexpr std::size_t kIpcMaxStringField = 1024;  // longest string a client accepts in a reply

enum class IpcVerb { Status, Health, Events };
const char* to_string(IpcVerb v);  // "STATUS" | "HEALTH" | "EVENTS"
// The complete verb allowlist, in documentation order.
const std::array<const char*, 3>& ipc_allowed_verbs();

struct IpcRequest {
    IpcVerb verb = IpcVerb::Status;
    int limit = 0;  // EVENTS only: 1..kIpcMaxEvents (kIpcDefaultEvents when omitted)
};

enum class IpcErrorCode {
    EmptyRequest,
    RequestTooLong,
    NoNewline,        // no terminating "\n" (within the limit), or newline in the middle
    EmbeddedNul,
    NonAscii,
    ControlCharacter,
    UnknownCommand,   // includes lowercase / mixed-case verbs
    ExtraTokens,      // too many tokens, or empty tokens (leading/trailing/double space)
    BadArgument,      // EVENTS argument not a decimal 1..200
    StoreUnavailable, // server side: the event store could not be read
    Internal,         // server side: unexpected failure
};
const char* to_string(IpcErrorCode c);  // stable upper-case code, e.g. "UNKNOWN_COMMAND"
// Fixed human text for a code (never contains request bytes).
const char* ipc_error_message(IpcErrorCode c);
std::optional<IpcErrorCode> ipc_error_from_string(std::string_view s);

struct IpcParseError {
    IpcErrorCode code = IpcErrorCode::Internal;
    std::string message;  // == ipc_error_message(code)
};

// `line` = the bytes read from the pipe, terminator included.
std::variant<IpcRequest, IpcParseError> parse_request(std::string_view line);
// Client side: the exact bytes to send ("EVENTS 20\n"; EVENTS without limit -> "EVENTS\n").
std::string render_request(const IpcRequest& r);

// --- server-side rendering (each returns one line, "\n"-terminated, <= kIpcMaxResponseBytes) ----
std::string render_ipc_status(const ObserverStatus& s);
std::string render_ipc_health(const ObserverStatus& s);
// `events` newest first (as EventStore::recent_events returns them); `limit` is what was asked.
std::string render_ipc_events(const std::vector<StoredEvent>& events, int limit);
std::string render_ipc_error(IpcVerb verb, IpcErrorCode code);
std::string render_ipc_parse_error(const IpcParseError& e);  // "request":""

// "OK" | "DEGRADED" | "STARTING" | "STOPPING" | "STOPPED": coarse health derived from a status.
// DEGRADED = running but store_errors / snapshot_errors > 0, or no poll succeeded yet.
const char* health_of(const ObserverStatus& s);

// --- client-side ----------------------------------------------------------------------------
struct IpcHealth {
    std::string health;
    std::string state;
    long long store_errors = 0;
    long long snapshot_errors = 0;
};

struct IpcEventsData {
    int limit = 0;
    bool truncated = false;
    std::vector<StoredEvent> events;  // newest first
};

struct IpcResponse {
    bool ok = false;
    IpcVerb verb = IpcVerb::Status;
    // ok == false: the server's typed refusal
    IpcErrorCode error_code = IpcErrorCode::Internal;
    std::string error_message;
    // ok == true: exactly the member matching `verb` is set
    std::optional<ObserverStatus> status;
    std::optional<IpcHealth> health;
    std::optional<IpcEventsData> events;
};

struct IpcParsedResponse {
    bool valid = false;   // false = the bytes are NOT a well-formed reply (treat as unreachable/corrupt)
    std::string error;    // why it was rejected (never echoes the reply)
    IpcResponse response;
};

// Strict validation of a reply: size <= kIpcMaxResponseBytes, one trailing newline at most, valid
// JSON, schema_version 1, command "service-ipc", "request" == `expected`, field types, string
// lengths <= kIpcMaxStringField, at most kIpcMaxEvents events. Unknown extra members are ignored
// (additive schema).
IpcParsedResponse parse_response(std::string_view line, IpcVerb expected);

}  // namespace metasec
