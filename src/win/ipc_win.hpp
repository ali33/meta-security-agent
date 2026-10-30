#pragma once
// MVP-4 (Windows half): the named pipe that carries the read-only line protocol of core/ipc_proto.hpp.
//
// Server (inside the service / `service run --console`):
//   * byte-mode pipe, overlapped I/O, at most kPipeMaxInstances instances, one worker thread each
//     (fixed: no thread or memory growth under load), small buffers;
//   * first instance created with FILE_FLAG_FIRST_PIPE_INSTANCE: if another process already owns the
//     name (squatting) start() fails and the caller reports it and keeps observing;
//   * PIPE_REJECT_REMOTE_CLIENTS plus an explicit DACL (kPipeSddlService below);
//   * every connection: bounded read (kPipeIoTimeoutMs), parse, answer, bounded write, bounded wait
//     for the client to close, disconnect. A slow or hostile client can occupy one instance for a few
//     seconds, never the observer, never the stop path (every wait also waits on the stop event).
// Client: SECURITY_IDENTIFICATION (the server may learn who we are, never act as us), bounded waits,
//   and for the DEFAULT pipe name the server's process id must be the service's (SCM-reported) id.
#include <windows.h>

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "../core/ipc_proto.hpp"
#include "../core/observer.hpp"
#include "../core/service_model.hpp"
#include "../core/store.hpp"

namespace metasec::win {

inline constexpr int kPipeMaxInstances = 4;
inline constexpr DWORD kPipeIoTimeoutMs = 2000;
inline constexpr DWORD kPipeBufferBytes = 4096;
// CreateNamedPipeW flags. Exposed so tests can assert the security-relevant ones.
inline constexpr DWORD kPipeOpenModeFirst = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
inline constexpr DWORD kPipeOpenModeNext = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
inline constexpr DWORD kPipePipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
// Rights an ordinary interactive user needs: read, write, read attributes, synchronize. NOT
// FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE for pipes): users can never create instances.
inline constexpr DWORD kPipeClientAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

// DACL + mandatory label of the service pipe: network logons denied, SYSTEM and Administrators full
// control, interactive users read/write (0x120083 = kPipeClientAccess | READ_CONTROL), medium integrity
// label with no-write-up. Nothing for Everyone / Anonymous / network. At runtime one more ACE is added:
// full control for the server's own identity (Config::server_sid), see there.
inline constexpr const wchar_t* kPipeSddlService =
    L"D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;IU)S:(ML;;NW;;;ME)";

std::wstring pipe_path(const std::string& pipe_name);  // L"\\\\.\\pipe\\<name>"

struct IpcCounters {  // debug counters: no request content, no identities
    long long connections = 0;
    long long served = 0;
    long long rejected = 0;   // malformed / oversize / unknown requests answered with an error
    long long timeouts = 0;   // client too slow or silent
    long long io_errors = 0;
};

class IpcServer {
public:
    struct Config {
        std::wstring pipe_path;         // full path, from pipe_path()
        // The account this server runs as (the service SID NT SERVICEMetaSecAgent, or the invoking user in foreground
        // mode). It gets full control so the worker threads can create the further pipe instances: CREATE_PIPE_INSTANCE
        // is otherwise reserved to SYSTEM and Administrators, and LocalService is neither.
        std::wstring server_sid;
        int instances = kPipeMaxInstances;
        DWORD io_timeout_ms = kPipeIoTimeoutMs;
    };
    struct Hooks {
        std::function<ObserverStatus()> status;
        std::function<StoreResult<std::vector<StoredEvent>>(int limit)> recent_events;
    };

    IpcServer(Config cfg, Hooks hooks);
    ~IpcServer();
    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    // Creates the instances and starts the workers. false + `error` when the pipe cannot be created
    // (name taken by another process, access denied...).
    bool start(std::string& error);
    // Idempotent. Returns after every worker thread has ended.
    void stop();
    IpcCounters counters() const;
    int instances() const { return static_cast<int>(pipes_.size()); }  // pipe instances actually created

private:
    void worker(HANDLE pipe);
    void serve(HANDLE pipe, HANDLE io_event);

    Config cfg_;
    Hooks hooks_;
    HANDLE stop_event_ = nullptr;
    std::vector<HANDLE> pipes_;
    std::vector<std::thread> threads_;
    std::atomic<long long> connections_{0}, served_{0}, rejected_{0}, timeouts_{0}, io_errors_{0};
};

// ---- client ----------------------------------------------------------------------------------
struct IpcClientOptions {
    std::string pipe_name;  // empty = kDefaultPipeName
    DWORD timeout_ms = kPipeIoTimeoutMs;
    // Called with the server's process id once connected. false => reply is not trusted
    // (reason PIPE_SERVER_NOT_SERVICE). Empty = no check (explicit --pipe-name, foreground tests).
    std::function<bool(DWORD server_pid)> verify_server;
};

struct IpcRawReply {
    IpcReach reach = IpcReach::NotTried;
    std::string reason;
    std::string line;  // the reply, terminator included, when reach == Ok
};
IpcRawReply ipc_call(const IpcClientOptions& opt, const std::string& request_bytes);

IpcSnapshot ipc_fetch_status(const IpcClientOptions& opt);
ServiceEventsReport ipc_fetch_events(const IpcClientOptions& opt, int limit, const std::string& observed_at_utc);

}  // namespace metasec::win
