#include "service_win.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

#include "../core/render.hpp"
#include "../core/service_model.hpp"
#include "collect.hpp"

namespace metasec::win {

namespace {

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string now_utc() { return format_utc(std::chrono::system_clock::now()); }

long long now_epoch() {
    return static_cast<long long>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

bool write_stdout(const std::string& s) {
    return std::fwrite(s.data(), 1, s.size(), stdout) == s.size() && std::fflush(stdout) == 0;
}

// ---- foreground stop (Ctrl+C / Ctrl+Break / console close) -------------------------------------
HANDLE g_console_stop = nullptr;
HANDLE g_console_done = nullptr;

BOOL WINAPI on_console_signal(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            if (g_console_stop) SetEvent(g_console_stop);
            return TRUE;
        case CTRL_CLOSE_EVENT:
            if (g_console_stop) SetEvent(g_console_stop);
            if (g_console_done) WaitForSingleObject(g_console_done, 3000);  // let the store close cleanly
            return TRUE;
        default: return FALSE;
    }
}

class ConsoleStop {
public:
    ConsoleStop() {
        g_console_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_console_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ok_ = g_console_stop && g_console_done && SetConsoleCtrlHandler(on_console_signal, TRUE);
    }
    ~ConsoleStop() {
        if (g_console_done) SetEvent(g_console_done);
        SetConsoleCtrlHandler(on_console_signal, FALSE);
        HANDLE stop = g_console_stop, done = g_console_done;
        g_console_stop = g_console_done = nullptr;
        if (stop) CloseHandle(stop);
        if (done) CloseHandle(done);
    }
    ConsoleStop(const ConsoleStop&) = delete;
    ConsoleStop& operator=(const ConsoleStop&) = delete;
    bool ok() const { return ok_; }
    HANDLE stop_event() const { return g_console_stop; }

private:
    bool ok_ = false;
};

// ---- SCM front end -----------------------------------------------------------------------------
std::mutex g_status_mu;
SERVICE_STATUS g_status{};
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
// Created once, never closed: the control handler may run on another thread at any moment, and the process ends
// right after ServiceMain returns, so there is no window in which the handle could be used after it was closed.
HANDLE g_stop_event = nullptr;
std::atomic<DWORD> g_service_exit{NO_ERROR};  // what ServiceMain reported as the Win32 exit code
std::string g_version;

// Reports `state`. Pending states carry an increasing checkpoint and a wait hint; the service accepts
// STOP, SHUTDOWN and PRESHUTDOWN only while RUNNING. Serialised: the control handler and ServiceMain both report.
void report(DWORD state, DWORD win32_exit = NO_ERROR, DWORD wait_hint_ms = 0) {
    std::lock_guard<std::mutex> lock(g_status_mu);
    if (!g_status_handle) return;
    static DWORD checkpoint = 0;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN) : 0;
    g_status.dwWin32ExitCode = win32_exit;
    g_status.dwServiceSpecificExitCode = 0;
    const bool pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    g_status.dwCheckPoint = pending ? ++checkpoint : 0;
    g_status.dwWaitHint = pending ? wait_hint_ms : 0;
    SetServiceStatus(g_status_handle, &g_status);
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_PRESHUTDOWN:
            report(SERVICE_STOP_PENDING, NO_ERROR, 20000);
            if (g_stop_event) SetEvent(g_stop_event);  // returns at once; the work happens on the worker thread
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE: {
            std::lock_guard<std::mutex> lock(g_status_mu);
            if (g_status_handle) SetServiceStatus(g_status_handle, &g_status);
            return NO_ERROR;
        }
        default: return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(kServiceNameW, control_handler, nullptr);
    if (!g_status_handle) return;  // nothing can be reported without a handle
    DWORD exit_code = NO_ERROR;
    HANDLE worker_done = nullptr;
    std::thread worker;
    try {
        report(SERVICE_START_PENDING, NO_ERROR, 10000);
        if (!harden_dll_search()) throw std::runtime_error("cannot restrict the DLL search path");
        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        worker_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_stop_event || !worker_done) throw std::runtime_error("cannot create events");

        HostConfig cfg;
        cfg.data_dir = service_data_dir();
        cfg.dir_mode = DirMode::Service;
        cfg.pipe_path = pipe_path(kDefaultPipeName);
        cfg.pipe_server_sid = service_sid_string(kServiceNameW);
        cfg.observer.version = g_version;
        cfg.stop_event = g_stop_event;
        cfg.snapshot = [] { return collect_status(std::chrono::system_clock::now()); };

        worker = std::thread([cfg, worker_done, &exit_code] {
            try {
                ComApartment com;  // all providers run on this thread, inside this apartment
                if (!com.ok()) {
                    exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
                } else {
                    const HostResult res = run_host(cfg);
                    // A host that ends by itself (not because the SCM asked) or on an error is a failure the SCM must see.
                    if (res.observer.stop == ObserverStop::Error) exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
                    else if (WaitForSingleObject(cfg.stop_event, 0) != WAIT_OBJECT_0) exit_code = ERROR_SERVICE_SPECIFIC_ERROR;
                }
            } catch (...) {
                exit_code = ERROR_EXCEPTION_IN_SERVICE;
            }
            SetEvent(worker_done);
        });
        report(SERVICE_RUNNING);

        // Keep the SCM informed while stopping: checkpoint grows every second until the worker is done.
        while (WaitForSingleObject(worker_done, 1000) == WAIT_TIMEOUT) {
            if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0) report(SERVICE_STOP_PENDING, NO_ERROR, 20000);
        }
        worker.join();
    } catch (...) {
        exit_code = ERROR_EXCEPTION_IN_SERVICE;
        if (g_stop_event) SetEvent(g_stop_event);
        if (worker.joinable()) worker.join();
    }
    if (worker_done) CloseHandle(worker_done);
    g_service_exit = exit_code;
    report(SERVICE_STOPPED, exit_code);
}

}  // namespace

bool harden_dll_search() {
    // Order matters little; both are checked. LocalService must never load a DLL from the current directory.
    const bool a = SetDllDirectoryW(L"") != FALSE;
    const bool b = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != FALSE;
    return a && b;
}

HostResult run_host(const HostConfig& cfg) {
    HostResult res;
    auto say = [&](const std::string& m) {
        if (cfg.log) cfg.log(m);
    };

    // Store: fail closed. A directory that is a junction, has a foreign owner or too-open rules is never opened.
    std::unique_ptr<EventStore> store;
    const DirCheck dir = prepare_data_dir(cfg.data_dir, cfg.dir_mode);
    if (!dir.ok) {
        res.store_error = dir.error;
    } else {
        StoreOpen so = EventStore::open(cfg.data_dir / "events.db");
        if (so.ok) {
            store = std::move(so.store);
            res.store_ok = true;
        } else {
            res.store_error = so.error;
        }
    }
    if (!res.store_ok) say("event store unavailable (observing without persistence): " + res.store_error);

    ObserverOptions oo = cfg.observer;
    if (!store) oo.store_unavailable_reason = res.store_error;
    const HANDLE stop = cfg.stop_event;
    ObserverHooks hooks;
    hooks.snapshot = cfg.snapshot;
    hooks.wait = [stop](int seconds) { return WaitForSingleObject(stop, static_cast<DWORD>(seconds) * 1000) == WAIT_TIMEOUT; };
    hooks.stop_requested = [stop] { return WaitForSingleObject(stop, 0) == WAIT_OBJECT_0; };
    hooks.now_utc = now_utc;
    hooks.now_epoch = now_epoch;
    Observer observer(store.get(), oo, hooks);

    EventStore* raw_store = store.get();
    IpcServer::Config pc;
    pc.pipe_path = cfg.pipe_path;
    pc.server_sid = cfg.pipe_server_sid;
    IpcServer::Hooks ph;
    ph.status = [&observer] { return observer.status(); };
    ph.recent_events = [raw_store](int limit) {
        if (!raw_store) {
            StoreResult<std::vector<StoredEvent>> r;
            r.error = "event store unavailable";
            return r;
        }
        return raw_store->recent_events(limit);
    };
    IpcServer server(std::move(pc), std::move(ph));
    res.pipe_ok = server.start(res.pipe_error);
    res.pipe_instances = server.instances();
    if (!res.pipe_ok) say("status pipe unavailable (observing anyway): " + res.pipe_error);

    res.observer = observer.run();
    server.stop();  // joins every pipe worker before the observer and the store go away
    res.final_status = observer.status();
    res.ipc = server.counters();
    store.reset();  // closes SQLite: WAL checkpointed
    return res;
}

int run_service_console(const ParsedArgs& args, const std::string& version) {
    if (!harden_dll_search()) {
        std::cerr << "meta-sec: cannot restrict the DLL search path\n";
        return kExitError;
    }
    ComApartment com;
    if (!com.ok()) {
        std::cerr << "meta-sec: COM initialisation failed: " << hresult_code(static_cast<std::uint32_t>(com.result())) << "\n";
        return kExitError;
    }
    ConsoleStop stop;
    if (!stop.ok()) {
        std::cerr << "meta-sec: cannot install the stop handler\n";
        return kExitError;
    }

    HostConfig cfg;
    cfg.dir_mode = DirMode::UserOnly;
    cfg.data_dir = args.data_dir.empty() ? dev_data_dir() : std::filesystem::path(utf8_to_wide(args.data_dir));
    if (cfg.data_dir.empty()) {
        std::cerr << "meta-sec: cannot determine the data directory\n";
        return kExitError;
    }
    std::error_code ec;
    if (!cfg.data_dir.is_absolute()) cfg.data_dir = std::filesystem::absolute(cfg.data_dir, ec);
    const std::string pipe_name = args.pipe_name.empty() ? std::string(kDefaultPipeName) : args.pipe_name;
    cfg.pipe_path = pipe_path(pipe_name);
    cfg.pipe_server_sid = current_user_sid_string();
    cfg.observer.interval_seconds = args.interval_seconds;
    cfg.observer.confirm_polls = args.confirm_polls;
    cfg.observer.max_polls = args.max_polls;
    cfg.observer.version = version;
    cfg.stop_event = stop.stop_event();
    cfg.snapshot = [] { return collect_status(std::chrono::system_clock::now()); };
    cfg.log = [](const std::string& m) { std::cerr << "meta-sec: " << sanitize_for_display(m) << "\n"; };

    std::cerr << "meta-sec: service run --console: pipe \\\\.\\pipe\\" << pipe_name << ", data dir "
              << sanitize_for_display(cfg.data_dir.string()) << ", every " << args.interval_seconds
              << "s (Ctrl+C to stop)\n";

    const HostResult res = run_host(cfg);

    const char* why = res.observer.stop == ObserverStop::MaxPolls ? "max_polls"
                      : res.observer.stop == ObserverStop::Interrupted ? "interrupted"
                                                                        : "error";
    const std::string line = now_utc() + " [STOPPED] " + why + " after " + std::to_string(res.observer.polls) + " polls, " +
                             std::to_string(res.observer.events_recorded) + " events, " +
                             std::to_string(res.observer.store_errors) + " store errors\n";
    if (!write_stdout(line)) {
        std::cerr << "meta-sec: failed to write output\n";
        return kExitError;
    }
    if (res.observer.stop == ObserverStop::Error) {
        std::cerr << "meta-sec: service run failed: " << sanitize_for_display(res.observer.error) << "\n";
        return kExitError;
    }
    return (res.store_ok && res.pipe_ok && res.observer.store_errors == 0) ? kExitOk : kExitIncomplete;
}

int run_service_scm(const std::string& version) {
    g_version = version;
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceNameW), service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            std::cerr << "meta-sec: 'service run --scm' is started by the Service Control Manager; use 'service run --console' in a terminal\n";
        else
            std::cerr << "meta-sec: cannot connect to the Service Control Manager (WIN32:" << GetLastError() << ")\n";
        return kExitError;
    }
    return g_service_exit == NO_ERROR ? kExitOk : kExitError;  // the process exit code mirrors what the SCM was told
}

}  // namespace metasec::win
