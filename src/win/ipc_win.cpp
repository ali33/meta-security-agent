#include "ipc_win.hpp"

#include <sddl.h>

#include <algorithm>
#include <cstring>
#include <variant>

#include "datadir_win.hpp"

namespace metasec::win {

static_assert((kPipePipeMode & PIPE_REJECT_REMOTE_CLIENTS) != 0, "the pipe must refuse remote clients");
static_assert((kPipeOpenModeFirst & FILE_FLAG_FIRST_PIPE_INSTANCE) != 0, "the first instance must detect squatting");
static_assert((kPipeOpenModeFirst & FILE_FLAG_OVERLAPPED) != 0 && (kPipeOpenModeNext & FILE_FLAG_OVERLAPPED) != 0,
              "bounded I/O needs overlapped pipes");
static_assert((kPipeClientAccess & FILE_APPEND_DATA) == 0, "clients must not be able to create pipe instances");

std::wstring pipe_path(const std::string& pipe_name) {
    std::wstring p = L"\\\\.\\pipe\\";
    for (char c : pipe_name) p += static_cast<wchar_t>(static_cast<unsigned char>(c));  // validated ASCII (cli.cpp)
    return p;
}

namespace {

struct LocalFreeDeleter {
    void operator()(void* p) const {
        if (p) LocalFree(p);
    }
};

enum class Io { Ok, Timeout, Stopped, Broken, Error };

// One overlapped read or write with a deadline (GetTickCount64 based) and an optional stop event.
// On timeout/stop the operation is cancelled and reaped before returning, so `buf` and `ev` are
// never touched by the kernel afterwards.
Io overlapped_io(HANDLE pipe, bool read, void* buf, DWORD len, DWORD& transferred, ULONGLONG deadline, HANDLE ev, HANDLE stop) {
    transferred = 0;
    ResetEvent(ev);
    OVERLAPPED ov{};
    ov.hEvent = ev;
    const BOOL started = read ? ReadFile(pipe, buf, len, nullptr, &ov) : WriteFile(pipe, buf, len, nullptr, &ov);
    if (!started) {
        const DWORD e = GetLastError();
        if (e == ERROR_BROKEN_PIPE || e == ERROR_NO_DATA || e == ERROR_PIPE_NOT_CONNECTED) return Io::Broken;
        if (e != ERROR_IO_PENDING) return Io::Error;
        const ULONGLONG now = GetTickCount64();
        const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, 0x7FFFFFFF));
        HANDLE handles[2] = {ev, stop};
        const DWORD w = WaitForMultipleObjects(stop ? 2 : 1, handles, FALSE, remaining);
        if (w != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            DWORD ignored = 0;
            GetOverlappedResult(pipe, &ov, &ignored, TRUE);  // reap: returns once the cancel is done
            return w == WAIT_TIMEOUT ? Io::Timeout : (w == WAIT_OBJECT_0 + 1 ? Io::Stopped : Io::Error);
        }
    }
    if (!GetOverlappedResult(pipe, &ov, &transferred, FALSE)) {
        const DWORD e = GetLastError();
        if (e == ERROR_BROKEN_PIPE || e == ERROR_NO_DATA || e == ERROR_PIPE_NOT_CONNECTED) return Io::Broken;
        return Io::Error;
    }
    return Io::Ok;
}

ULONGLONG deadline_in(DWORD ms) { return GetTickCount64() + ms; }

std::wstring service_sddl(const std::wstring& server_sid) {
    std::wstring s = kPipeSddlService;
    if (server_sid.empty()) return {};
    s.insert(s.find(L"S:"), L"(A;;GA;;;" + server_sid + L")");
    return s;
}

}  // namespace

IpcServer::IpcServer(Config cfg, Hooks hooks) : cfg_(std::move(cfg)), hooks_(std::move(hooks)) {}

IpcServer::~IpcServer() { stop(); }

bool IpcServer::start(std::string& error) {
    if (!threads_.empty() || !pipes_.empty()) {
        error = "already started";
        return false;
    }
    PSECURITY_DESCRIPTOR psd = nullptr;
    const std::wstring sddl = service_sddl(cfg_.server_sid);
    if (sddl.empty()) {
        error = "no server identity for the pipe access rules";
        return false;
    }
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd, nullptr)) {
        error = "pipe access rules rejected (WIN32:" + std::to_string(GetLastError()) + ")";
        return false;
    }
    std::unique_ptr<void, LocalFreeDeleter> psd_guard(psd);
    SECURITY_ATTRIBUTES sa{sizeof sa, psd, FALSE};

    const int n = std::clamp(cfg_.instances, 1, kPipeMaxInstances);
    for (int i = 0; i < n; ++i) {
        HANDLE h = CreateNamedPipeW(cfg_.pipe_path.c_str(), i == 0 ? kPipeOpenModeFirst : kPipeOpenModeNext, kPipePipeMode,
                                    static_cast<DWORD>(n), kPipeBufferBytes, kPipeBufferBytes, 0, &sa);
        if (h == INVALID_HANDLE_VALUE) {
            const DWORD e = GetLastError();
            if (i == 0) {
                // With FILE_FLAG_FIRST_PIPE_INSTANCE, "name already used by another process" is ACCESS_DENIED.
                error = e == ERROR_ACCESS_DENIED || e == ERROR_PIPE_BUSY
                            ? "the pipe name is already in use by another process (possible squatting); status pipe disabled"
                            : "cannot create the status pipe (WIN32:" + std::to_string(e) + ")";
                return false;
            }
            break;  // fewer instances is fine
        }
        pipes_.push_back(h);
    }
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_event_) {
        error = "cannot create the stop event";
        for (HANDLE h : pipes_) CloseHandle(h);
        pipes_.clear();
        return false;
    }
    try {
        for (HANDLE h : pipes_) threads_.emplace_back([this, h, reserved = (h == pipes_.front())] { worker(h, reserved); });
    } catch (...) {
        stop();
        error = "cannot start the pipe workers";
        return false;
    }
    return true;
}

void IpcServer::stop() {
    if (stop_event_) SetEvent(stop_event_);
    for (auto& t : threads_)
        if (t.joinable()) t.join();
    threads_.clear();
    for (HANDLE h : pipes_) CloseHandle(h);
    pipes_.clear();
    if (stop_event_) {
        CloseHandle(stop_event_);
        stop_event_ = nullptr;
    }
}

IpcCounters IpcServer::counters() const {
    return {connections_.load(), served_.load(), rejected_.load(), timeouts_.load(), io_errors_.load()};
}

void IpcServer::worker(HANDLE pipe, bool reserved) {
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ev) {
        ++io_errors_;
        return;
    }
    while (WaitForSingleObject(stop_event_, 0) != WAIT_OBJECT_0) {
        ResetEvent(ev);
        OVERLAPPED ov{};
        ov.hEvent = ev;
        bool connected = false;
        if (ConnectNamedPipe(pipe, &ov)) {
            connected = true;
        } else {
            const DWORD e = GetLastError();
            if (e == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (e == ERROR_IO_PENDING) {
                HANDLE handles[2] = {ev, stop_event_};
                const DWORD w = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                if (w == WAIT_OBJECT_0) {
                    DWORD ignored = 0;
                    connected = GetOverlappedResult(pipe, &ov, &ignored, FALSE) != FALSE;
                } else {
                    CancelIoEx(pipe, &ov);
                    DWORD ignored = 0;
                    GetOverlappedResult(pipe, &ov, &ignored, TRUE);
                    break;  // stop requested
                }
            }
        }
        if (connected) {
            ++connections_;
            try {
                serve(pipe, ev, reserved);
            } catch (...) {
                ++io_errors_;  // never let one connection take the worker (and the instance) down
            }
        } else {
            ++io_errors_;
            if (WaitForSingleObject(stop_event_, 100) == WAIT_OBJECT_0) break;  // back off, stay stoppable
        }
        DisconnectNamedPipe(pipe);
    }
    CloseHandle(ev);
}

void IpcServer::serve(HANDLE pipe, HANDLE io_event, bool reserved) {
    // 1. Read the request: at most kIpcMaxRequestBytes + 1 bytes, up to the first '\n', within the deadline.
    std::string req;
    // The whole request line must arrive quickly: a legitimate client writes it in the same breath it connects.
    // The reserved instance recycles twice as fast, so one instance is always free again within a fraction of a second.
    const ULONGLONG read_deadline = deadline_in(reserved ? cfg_.request_timeout_ms / 2 : cfg_.request_timeout_ms);
    char buf[kIpcMaxRequestBytes + 1];
    for (;;) {
        const DWORD want = static_cast<DWORD>(sizeof buf - req.size());
        DWORD got = 0;
        const Io r = overlapped_io(pipe, true, buf, want, got, read_deadline, io_event, stop_event_);
        if (r == Io::Timeout) { ++timeouts_; return; }
        if (r != Io::Ok) { if (r != Io::Stopped && r != Io::Broken) ++io_errors_; return; }
        req.append(buf, got);
        const std::size_t nl = req.find('\n');
        if (nl != std::string::npos) { req.resize(nl + 1); break; }  // anything pipelined after it is ignored
        if (req.size() >= sizeof buf) break;                          // too long: parse_request names it
        if (got == 0) return;
    }

    // 2. Answer. Failures to build the answer become a typed error, never a crash or a hang.
    std::string reply;
    try {
        const auto parsed = parse_request(req);
        if (const auto* pe = std::get_if<IpcParseError>(&parsed)) {
            ++rejected_;
            reply = render_ipc_parse_error(*pe);
        } else {
            const IpcRequest& rq = std::get<IpcRequest>(parsed);
            switch (rq.verb) {
                case IpcVerb::Status: reply = render_ipc_status(hooks_.status()); break;
                case IpcVerb::Health: reply = render_ipc_health(hooks_.status()); break;
                case IpcVerb::Events: {
                    const auto ev = hooks_.recent_events(rq.limit);
                    reply = ev.ok ? render_ipc_events(ev.value, rq.limit) : render_ipc_error(IpcVerb::Events, IpcErrorCode::StoreUnavailable);
                    break;
                }
            }
            ++served_;
        }
    } catch (...) {
        reply = render_ipc_parse_error({IpcErrorCode::Internal, ipc_error_message(IpcErrorCode::Internal)});
        ++io_errors_;
    }

    // 3. Write it, bounded. A client that does not read is cut off at the deadline.
    const ULONGLONG write_deadline = deadline_in(cfg_.io_timeout_ms * 2);
    std::size_t sent = 0;
    while (sent < reply.size()) {
        DWORD put = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(reply.size() - sent, 64 * 1024));
        const Io w = overlapped_io(pipe, false, reply.data() + sent, chunk, put, write_deadline, io_event, stop_event_);
        if (w == Io::Timeout) { ++timeouts_; return; }
        if (w != Io::Ok) { if (w != Io::Stopped && w != Io::Broken) ++io_errors_; return; }
        sent += put;
    }

    // 4. Let the client finish: wait (bounded) until it closes its end, discarding anything more it sends
    //    (this also lets a client that is still writing an oversize request complete and read our error).
    //    DisconnectNamedPipe would otherwise throw away a reply the client has not read yet.
    const ULONGLONG drain_deadline = deadline_in(reserved ? cfg_.request_timeout_ms / 2 : cfg_.request_timeout_ms);
    for (;;) {
        DWORD got = 0;
        const Io r = overlapped_io(pipe, true, buf, sizeof buf, got, drain_deadline, io_event, stop_event_);
        if (r != Io::Ok) {
            if (r == Io::Timeout) ++timeouts_;
            return;
        }
    }
}

// ---- client ----------------------------------------------------------------------------------

IpcRawReply ipc_call(const IpcClientOptions& opt, const std::string& request_bytes) {
    IpcRawReply out;
    const std::wstring path = pipe_path(opt.pipe_name.empty() ? kDefaultPipeName : opt.pipe_name);
    const ULONGLONG deadline = deadline_in(opt.timeout_ms);

    HANDLE h = INVALID_HANDLE_VALUE;
    for (;;) {
        // IDENTIFICATION: the server can query who we are but never act with our rights.
        h = CreateFileW(path.c_str(), kPipeClientAccess, 0, nullptr, OPEN_EXISTING,
                        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        const DWORD e = GetLastError();
        const ULONGLONG now = GetTickCount64();
        if (e == ERROR_PIPE_BUSY && now < deadline) {
            WaitNamedPipeW(path.c_str(), static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, 500)));
            continue;
        }
        if (e == ERROR_ACCESS_DENIED) {
            out.reach = IpcReach::AccessDenied;
            out.reason = "access to the status pipe was denied";
        } else {
            out.reach = IpcReach::Unreachable;
            out.reason = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? "status pipe not found"
                         : e == ERROR_PIPE_BUSY                                    ? "status pipe is busy"
                                                                                   : "WIN32:" + std::to_string(e);
        }
        return out;
    }
    struct Closer {
        HANDLE h;
        ~Closer() { CloseHandle(h); }
    } closer{h};

    if (opt.verify_server) {
        ULONG pid = 0;
        if (!GetNamedPipeServerProcessId(h, &pid) || !opt.verify_server(pid)) {
            out.reach = IpcReach::InvalidReply;
            out.reason = "PIPE_SERVER_NOT_SERVICE";
            return out;
        }
    }
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ev) {
        out.reach = IpcReach::Unreachable;
        out.reason = "WIN32:" + std::to_string(GetLastError());
        return out;
    }
    struct EvCloser {
        HANDLE h;
        ~EvCloser() { CloseHandle(h); }
    } ev_closer{ev};

    std::size_t sent = 0;
    while (sent < request_bytes.size()) {
        DWORD put = 0;
        const Io w = overlapped_io(h, false, const_cast<char*>(request_bytes.data()) + sent,
                                   static_cast<DWORD>(request_bytes.size() - sent), put, deadline, ev, nullptr);
        if (w != Io::Ok) {
            out.reach = IpcReach::Unreachable;
            out.reason = w == Io::Timeout ? "timed out sending the request" : "status pipe closed while sending";
            return out;
        }
        sent += put;
    }

    std::string line;
    char buf[4096];
    for (;;) {
        DWORD got = 0;
        const Io r = overlapped_io(h, true, buf, sizeof buf, got, deadline, ev, nullptr);
        if (r == Io::Timeout) {
            out.reach = IpcReach::Unreachable;
            out.reason = "timed out waiting for the reply";
            return out;
        }
        if (r == Io::Broken) break;  // server closed: judge what we have
        if (r != Io::Ok) {
            out.reach = IpcReach::Unreachable;
            out.reason = "status pipe read failed";
            return out;
        }
        line.append(buf, got);
        if (line.size() > kIpcMaxResponseBytes) {
            out.reach = IpcReach::InvalidReply;
            out.reason = "reply larger than the allowed maximum";
            return out;
        }
        if (!line.empty() && line.back() == '\n') break;
    }
    if (line.empty() || line.back() != '\n') {
        out.reach = IpcReach::InvalidReply;
        out.reason = "reply incomplete";
        return out;
    }
    out.reach = IpcReach::Ok;
    out.line = std::move(line);
    return out;
}

IpcSnapshot ipc_fetch_status(const IpcClientOptions& opt) {
    IpcSnapshot snap;
    const IpcRawReply raw = ipc_call(opt, render_request({IpcVerb::Status, 0}));
    if (raw.reach != IpcReach::Ok) {
        snap.reach = raw.reach;
        snap.reason = raw.reason;
        return snap;
    }
    const IpcParsedResponse p = parse_response(raw.line, IpcVerb::Status);
    if (!p.valid) {
        snap.reach = IpcReach::InvalidReply;
        snap.reason = p.error;
    } else if (!p.response.ok || !p.response.status) {
        snap.reach = IpcReach::InvalidReply;
        snap.reason = std::string("server refused the request: ") + to_string(p.response.error_code);
    } else {
        snap.reach = IpcReach::Ok;
        snap.status = *p.response.status;
    }
    return snap;
}

ServiceEventsReport ipc_fetch_events(const IpcClientOptions& opt, int limit, const std::string& observed_at_utc) {
    ServiceEventsReport rep;
    rep.observed_at_utc = observed_at_utc;
    rep.limit = limit;
    const IpcRawReply raw = ipc_call(opt, render_request({IpcVerb::Events, limit}));
    if (raw.reach != IpcReach::Ok) {
        rep.reach = raw.reach;
        rep.reason = raw.reason;
        return rep;
    }
    const IpcParsedResponse p = parse_response(raw.line, IpcVerb::Events);
    if (!p.valid) {
        rep.reach = IpcReach::InvalidReply;
        rep.reason = p.error;
    } else if (!p.response.ok || !p.response.events) {
        rep.reach = IpcReach::InvalidReply;
        rep.reason = std::string("server refused the request: ") + to_string(p.response.error_code);
    } else {
        rep.reach = IpcReach::Ok;
        rep.data = *p.response.events;
    }
    return rep;
}

}  // namespace metasec::win
