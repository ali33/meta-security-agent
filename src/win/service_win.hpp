#pragma once
// MVP-4 (Windows half): the service host. One code path, two front ends:
//   * `service run --scm`      started by the Service Control Manager (StartServiceCtrlDispatcherW)
//   * `service run --console`  foreground, stops on Ctrl+C / Ctrl+Break / --max-polls (development, tests)
// Both call run_host(): prepare + open the data directory, start the pipe server, run the Observer on the
// calling thread until the stop event is signalled (or max_polls), then stop the pipe, join, close the store.
#include <windows.h>

#include <filesystem>
#include <functional>
#include <string>

#include "../core/cli.hpp"
#include "../core/observer.hpp"
#include "../core/types.hpp"
#include "datadir_win.hpp"
#include "ipc_win.hpp"

namespace metasec::win {

struct HostConfig {
    std::filesystem::path data_dir;
    DirMode dir_mode = DirMode::Service;
    std::wstring pipe_path;
    std::wstring pipe_server_sid;  // service SID (SCM) or the invoking user (foreground / tests): owns the pipe
    ObserverOptions observer;
    std::function<StatusReport()> snapshot;  // real: collect_status (caller owns the COM apartment)
    HANDLE stop_event = nullptr;             // manual-reset; signalled = stop
    std::function<void(const std::string&)> log;  // diagnostics sink (stderr in --console, null in the service)
};

struct HostResult {
    ObserverResult observer;
    ObserverStatus final_status;
    bool store_ok = false;
    std::string store_error;
    bool pipe_ok = false;
    std::string pipe_error;
    int pipe_instances = 0;  // pipe instances created (kPipeMaxInstances when all went well)
    IpcCounters ipc;
};

// Blocks until stop. Never throws for expected failures: a data directory or store that cannot be used
// leaves the service observing without persistence (store_errors visible through the pipe); a pipe that
// cannot be created is reported and the observer keeps running.
HostResult run_host(const HostConfig& cfg);

// Process-wide hardening for service modes: system32-only DLL search, no current-directory search.
// false if Windows refused either call (callers then do not start).
bool harden_dll_search();

// `service run --console`: returns the process exit code (0 ok, 3 degraded, 2 failure).
int run_service_console(const ParsedArgs& args, const std::string& version);
// `service run --scm`: hands the thread to the SCM dispatcher; returns when the service has stopped.
int run_service_scm(const std::string& version);

}  // namespace metasec::win
