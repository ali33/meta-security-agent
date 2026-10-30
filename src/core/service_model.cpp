#include "service_model.hpp"

#include <algorithm>
#include <cctype>
#include <format>

#include "json.hpp"
#include "render.hpp"

namespace metasec {

namespace {

std::string q(std::string_view s) { return "\"" + json_escape(s) + "\""; }

// Terminal-safe: control characters never reach the console.
std::string printable(std::string_view s) { return strip_unsafe_display(s); }

std::string clip(std::string_view s, std::size_t n) {
    std::string o = printable(s);
    if (o.size() > n) {
        o = truncate_utf8(o, n);
        o += "...";
    }
    return o;
}

std::string bool_json(const std::optional<bool>& b) { return b ? (*b ? "true" : "false") : "null"; }

const char* overall_text(Overall o) { return to_string(o); }

std::string tag_of(const std::string& kind) {
    if (kind == "change") return "CHANGE";
    if (kind == "observation_lost") return "OBSERVATION LOST";
    if (kind == "observation_restored") return "OBSERVATION RESTORED";
    if (kind == "check_added") return "CHECK ADDED";
    if (kind == "check_removed") return "CHECK REMOVED";
    if (kind == kLifecycleStarted) return "SERVICE STARTED";
    if (kind == kLifecycleStopped) return "SERVICE STOPPED";
    return "EVENT";
}

std::string state_or_absent(const std::string& s) { return s.empty() ? "(absent)" : clip(s, 32); }

}  // namespace

std::string strip_unsafe_display(std::string_view s) {
    std::string o;
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        auto at = [&](std::size_t k) { return i + k < s.size() ? static_cast<unsigned char>(s[i + k]) : 0; };
        if (c < 0x20 || c == 0x7F) {  // ASCII controls (ESC, CR, LF, NUL...)
            o += '?';
            ++i;
        } else if (c == 0xC2 && at(1) >= 0x80 && at(1) <= 0x9F) {  // C1 controls (U+0080..U+009F, includes CSI U+009B)
            o += '?';
            i += 2;
        } else if (c == 0xD8 && at(1) == 0x9C) {  // U+061C arabic letter mark
            o += '?';
            i += 2;
        } else if (c == 0xE2 && at(1) == 0x80 && (at(2) == 0x8E || at(2) == 0x8F || (at(2) >= 0xAA && at(2) <= 0xAE))) {
            o += '?';  // U+200E/F marks, U+202A..U+202E embeddings and overrides
            i += 3;
        } else if (c == 0xE2 && at(1) == 0x81 && at(2) >= 0xA6 && at(2) <= 0xA9) {  // U+2066..U+2069 isolates
            o += '?';
            i += 3;
        } else {
            o += s[i];
            ++i;
        }
    }
    return o;
}

const char* to_string(InstallState s) { return s == InstallState::Installed ? "INSTALLED" : "NOT_INSTALLED"; }

const char* to_string(RunState s) {
    switch (s) {
        case RunState::Stopped: return "STOPPED";
        case RunState::StartPending: return "START_PENDING";
        case RunState::Running: return "RUNNING";
        case RunState::StopPending: return "STOP_PENDING";
        case RunState::ContinuePending: return "CONTINUE_PENDING";
        case RunState::PausePending: return "PAUSE_PENDING";
        case RunState::Paused: return "PAUSED";
        case RunState::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char* to_string(StartType s) {
    switch (s) {
        case StartType::Auto: return "AUTO";
        case StartType::AutoDelayed: return "AUTO_DELAYED";
        case StartType::Manual: return "MANUAL";
        case StartType::Disabled: return "DISABLED";
        case StartType::Unknown: return "UNKNOWN";
    }
    return "UNKNOWN";
}

const char* to_string(IpcReach r) {
    switch (r) {
        case IpcReach::NotTried: return "NOT_TRIED";
        case IpcReach::Ok: return "OK";
        case IpcReach::Unreachable: return "UNREACHABLE";
        case IpcReach::AccessDenied: return "ACCESS_DENIED";
        case IpcReach::InvalidReply: return "INVALID_REPLY";
    }
    return "UNREACHABLE";
}

const char* to_string(ServiceVerdict v) {
    switch (v) {
        case ServiceVerdict::NotInstalled: return "NOT_INSTALLED";
        case ServiceVerdict::Stopped: return "STOPPED";
        case ServiceVerdict::Running: return "RUNNING";
        case ServiceVerdict::RunningWithIssues: return "RUNNING_WITH_ISSUES";
        case ServiceVerdict::Pending: return "PENDING";
        case ServiceVerdict::IpcUnavailable: return "IPC_UNAVAILABLE";
        case ServiceVerdict::QueryFailed: return "QUERY_FAILED";
        case ServiceVerdict::UnexpectedState: return "UNEXPECTED_STATE";
    }
    return "QUERY_FAILED";
}

std::string redact_binary_path(const std::string& path) {
    std::string p = printable(path);
    // "...\Users\<name>\..." -> "...\Users\<user>\..." (the profile name is a person's account name)
    std::string low = p;
    std::transform(low.begin(), low.end(), low.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const char* marker : {"\\users\\", "/users/"}) {
        const std::size_t at = low.find(marker);
        if (at == std::string::npos) continue;
        const std::size_t begin = at + std::char_traits<char>::length(marker);
        std::size_t end = begin;
        while (end < p.size() && p[end] != '\\' && p[end] != '/') ++end;
        if (end > begin) p.replace(begin, end - begin, "<user>");
        break;
    }
    if (p.size() > kDataDirMaxLen) {
        p = truncate_utf8(p, kDataDirMaxLen);
        p += "...";
    }
    return p;
}

std::string service_approval_prompt_text(bool install, const std::string& actor, bool elevated) {
    return service_approval_prompt_text(install, actor, elevated, {}, {});
}

std::string service_approval_prompt_text(bool install, const std::string& actor, bool elevated, const std::string& image_path,
                                         const std::string& account) {
    std::string o;
    if (install) {
        o += std::format("About to INSTALL the Windows service '{}' (a background observer).\n", kServiceName);
        o += "  Effect        : registers this meta-sec.exe with the Service Control Manager (starts automatically).\n";
        o += "                  It only reads status and stores small change events locally; it changes no setting.\n";
    } else {
        o += std::format("About to UNINSTALL the Windows service '{}'.\n", kServiceName);
        o += "  Effect        : stops and removes the service registration. Stored events are left on disk.\n";
    }
    if (!image_path.empty()) o += std::format("  Command line  : {}\n", clip(image_path, 300));
    if (!account.empty()) o += std::format("  Runs as       : {}\n", clip(account, 120));
    o += std::format("  Approving as  : {}\n", printable(actor));
    if (!elevated) o += "  Note          : this process is not elevated; Windows will probably deny the request.\n";
    o += std::format("To approve, type exactly  {}  and press Enter. Anything else cancels.\n> ",
                     install ? kServiceInstallPhrase : kServiceUninstallPhrase);
    return o;
}

ServiceStatusReport build_service_status_report(const std::string& observed_at_utc, const ServiceInfo& svc,
                                                const IpcSnapshot& ipc) {
    ServiceStatusReport r;
    r.observed_at_utc = observed_at_utc;
    r.service = svc;
    r.ipc = ipc;
    auto set = [&](ServiceVerdict v, Overall o, std::string msg) {
        r.verdict = v;
        r.overall = o;
        r.exit_code = exit_code_for(o);
        r.message = std::move(msg);
    };
    if (!svc.query_ok) {
        set(ServiceVerdict::QueryFailed, Overall::Incomplete,
            "could not query the Service Control Manager (" + clip(svc.query_error.empty() ? "unknown error" : svc.query_error, 80) +
                "); whether the service is installed or running is unknown. Standalone commands still work.");
        return r;
    }
    if (svc.install == InstallState::NotInstalled) {
        set(ServiceVerdict::NotInstalled, Overall::Observed,
            "service is not installed; standalone commands (status/audit/watch/scan) work without it");
        return r;
    }
    switch (svc.run) {
        case RunState::Stopped: {
            std::string m = "service is installed but not running; no background events are being recorded. "
                            "Standalone commands (status/audit/watch/scan) still work";
            if (svc.start_type == StartType::Disabled) m += ". Its start type is DISABLED";
            set(ServiceVerdict::Stopped, Overall::Observed, m);
            return r;
        }
        case RunState::StartPending:
        case RunState::StopPending:
        case RunState::ContinuePending:
        case RunState::PausePending:
            set(ServiceVerdict::Pending, Overall::Incomplete,
                std::string("service is changing state (") + to_string(svc.run) + "); try again in a few seconds");
            return r;
        case RunState::Paused:
        case RunState::Unknown:
            set(ServiceVerdict::UnexpectedState, Overall::Incomplete,
                std::string("service reports an unexpected state (") + to_string(svc.run) + "); its health is unknown");
            return r;
        case RunState::Running: break;
    }
    if (ipc.reach == IpcReach::Ok && ipc.status) {
        const ObserverStatus& s = *ipc.status;
        if (s.store_errors > 0 || s.snapshot_errors > 0) {
            set(ServiceVerdict::RunningWithIssues, Overall::ObservedWithIssues,
                std::format("service is running, but reports {} store error(s) and {} snapshot error(s); last error: {}",
                            s.store_errors, s.snapshot_errors, s.last_error.empty() ? "(none)" : clip(s.last_error, 160)));
        } else {
            set(ServiceVerdict::Running, Overall::Observed, "service is running and observing");
        }
        return r;
    }
    const std::string why = ipc.reach == IpcReach::NotTried ? std::string("not queried")
                                                            : std::string(to_string(ipc.reach)) +
                                                                  (ipc.reason.empty() ? "" : ": " + clip(ipc.reason, 120));
    set(ServiceVerdict::IpcUnavailable, Overall::Incomplete,
        "service is running, but its status pipe could not be read (" + why +
            "); events and health are unknown. Standalone commands still work");
    return r;
}

std::string render_service_status_json(const ServiceStatusReport& r, const std::string& version) {
    const ServiceInfo& s = r.service;
    std::string o = std::format(R"({{"schema_version":{},"command":"service status","product":{},"version":{},)"
                                R"("mode":"standalone","observed_at_utc":{},)",
                                kSchemaVersion, q(kProduct), q(version), q(r.observed_at_utc));
    o += std::format(
        R"("service":{{"name":{},"query_ok":{},"query_error":{},"installed":{},"run_state":{},"start_type":{},)"
        R"("account":{},"binary_path":{},"binary_matches_cli":{}}},)",
        q(kServiceName), s.query_ok ? "true" : "false", q(clip(s.query_error, 80)),
        s.install == InstallState::Installed ? "true" : "false", q(to_string(s.run)), q(to_string(s.start_type)),
        q(clip(s.account, 120)), q(s.install == InstallState::Installed ? redact_binary_path(s.binary_path) : ""),
        bool_json(s.binary_matches_cli));
    if (r.ipc.reach == IpcReach::Ok && r.ipc.status) {
        const ObserverStatus& st = *r.ipc.status;
        o += std::format(
            R"("ipc":{{"reachable":true,"reach":"OK","reason":"","health":{},"state":{},"started_utc":{},)"
            R"("last_observation_utc":{},"polls":{},"events_total":{},"store_errors":{},"snapshot_errors":{},)"
            R"("last_error":{},"service_overall":{},"service_version":{}}},)",
            q(health_of(st)), q(to_string(st.state)), q(clip(st.started_utc, 40)), q(clip(st.last_observation_utc, 40)),
            st.polls, st.events_total, st.store_errors, st.snapshot_errors, q(clip(st.last_error, 160)),
            st.overall ? q(to_string(*st.overall)) : "null", q(clip(st.version, 40)));
    } else {
        o += std::format(R"("ipc":{{"reachable":false,"reach":{},"reason":{}}},)", q(to_string(r.ipc.reach)),
                         q(clip(r.ipc.reason, 120)));
    }
    o += std::format(R"("verdict":{},"message":{},"overall":{}}})", q(to_string(r.verdict)), q(r.message),
                     q(overall_text(r.overall)));
    return o + "\n";
}

std::string render_service_status_text(const ServiceStatusReport& r, const std::string& version) {
    const ServiceInfo& s = r.service;
    std::string o = std::format("{} v{} | Standalone | Read-only | Service\n", kProduct, version);
    o += std::format("Observed at : {}\n", printable(r.observed_at_utc));
    if (!s.query_ok) {
        o += std::format("Service     : {} - could not be queried ({})\n", kServiceName, clip(s.query_error, 80));
    } else if (s.install == InstallState::NotInstalled) {
        o += std::format("Service     : {} - not installed\n", kServiceName);
    } else {
        o += std::format("Service     : {} - installed, {} (start: {}, account: {})\n", kServiceName, to_string(s.run),
                         to_string(s.start_type), s.account.empty() ? "unknown" : clip(s.account, 120));
        o += std::format("Binary      : {}{}\n", redact_binary_path(s.binary_path),
                         s.binary_matches_cli ? (*s.binary_matches_cli ? "  (this meta-sec.exe)" : "  (NOT this meta-sec.exe)") : "");
    }
    if (r.ipc.reach == IpcReach::Ok && r.ipc.status) {
        const ObserverStatus& st = *r.ipc.status;
        o += std::format("Observer    : {} ({}), since {}\n", to_string(st.state), health_of(st), clip(st.started_utc, 40));
        o += std::format("Last poll   : {} ({} polls, overall {})\n",
                         st.last_observation_utc.empty() ? "none yet" : clip(st.last_observation_utc, 40), st.polls,
                         st.overall ? to_string(*st.overall) : "n/a");
        o += std::format("Events      : {} stored in total, {} store errors, {} snapshot errors\n", st.events_total,
                         st.store_errors, st.snapshot_errors);
        if (!st.last_error.empty()) o += std::format("Last error  : {}\n", clip(st.last_error, 160));
        o += std::format("Service ver : {}\n", clip(st.version, 40));
    } else if (r.ipc.reach != IpcReach::NotTried) {
        o += std::format("Observer    : not readable ({}{})\n", to_string(r.ipc.reach),
                         r.ipc.reason.empty() ? "" : ": " + clip(r.ipc.reason, 120));
    }
    o += std::format("Result      : {} - {}\n", overall_text(r.overall), r.message);
    return o;
}

int service_events_exit_code(const ServiceEventsReport& r) {
    return r.reach == IpcReach::Ok && r.data ? kExitOk : kExitIncomplete;
}

std::string render_service_events_json(const ServiceEventsReport& r, const std::string& version) {
    std::string o = std::format(R"({{"schema_version":{},"command":"service events","product":{},"version":{},)"
                                R"("mode":"standalone","observed_at_utc":{},"limit":{},)",
                                kSchemaVersion, q(kProduct), q(version), q(r.observed_at_utc), r.limit);
    const bool ok = r.reach == IpcReach::Ok && r.data;
    if (!ok) {
        o += std::format(R"("reach":{},"reason":{},"truncated":false,"count":0,"events":[],"overall":"INCOMPLETE"}})",
                         q(to_string(r.reach)), q(clip(r.reason, 120)));
        return o + "\n";
    }
    o += std::format(R"("reach":"OK","reason":"","truncated":{},"count":{},"events":[)",
                     r.data->truncated ? "true" : "false", r.data->events.size());
    bool first = true;
    for (const auto& e : r.data->events) {
        if (!first) o += ',';
        first = false;
        std::string ev = "{";
        for (std::size_t i = 0; i < e.evidence.size(); ++i) {
            if (i) ev += ',';
            ev += q(e.evidence[i].first) + ":" + q(e.evidence[i].second);
        }
        ev += '}';
        o += std::format(
            R"({{"id":{},"kind":{},"observed_at_utc":{},"first_observed_at_utc":{},"check_id":{},"from":{},"to":{},)"
            R"("confirmations":{},"source":{},"error_code":{},"evidence":{}}})",
            e.id, q(e.kind), q(e.observed_at_utc), q(e.first_observed_at_utc), q(e.check_id),
            e.from_state.empty() ? "null" : q(e.from_state), e.to_state.empty() ? "null" : q(e.to_state),
            e.confirmations, q(e.source), q(e.error_code), ev);
    }
    o += R"(],"overall":"OBSERVED"})";
    return o + "\n";
}

std::string render_service_events_text(const ServiceEventsReport& r, const std::string& version) {
    std::string o = std::format("{} v{} | Standalone | Read-only | Service events\n", kProduct, version);
    if (!(r.reach == IpcReach::Ok && r.data)) {
        o += std::format("Could not read events from the service ({}{}). Standalone commands still work.\n",
                         to_string(r.reach), r.reason.empty() ? "" : ": " + clip(r.reason, 120));
        return o;
    }
    if (r.data->events.empty()) o += "No events recorded yet.\n";
    for (const auto& e : r.data->events) {
        o += std::format("{} [{}]", printable(e.observed_at_utc), tag_of(e.kind));
        if (!e.check_id.empty())
            o += std::format(" {}: {} -> {}", clip(e.check_id, 128), state_or_absent(e.from_state), state_or_absent(e.to_state));
        for (const auto& [k, v] : e.evidence)
            if (k == "detected_after_restart") o += " (detected after service restart)";
        if (!e.error_code.empty()) o += " error " + clip(e.error_code, 128);
        o += "\n";
    }
    if (r.data->truncated) o += "(older events omitted: reply size limit)\n";
    return o;
}

}  // namespace metasec
