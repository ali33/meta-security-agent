#include "service_install.hpp"

#include <algorithm>
#include <cctype>
#include <format>

#include "json.hpp"
#include "render.hpp"

namespace metasec {

namespace {

std::string q(std::string_view s) { return "\"" + json_escape(s) + "\""; }

std::string printable(std::string_view s) { return strip_unsafe_display(s); }

std::string clip(std::string_view s, std::size_t n) {
    std::string o = printable(s);
    if (o.size() > n) {
        o = truncate_utf8(o, n);
        o += "...";
    }
    return o;
}

const char* b(bool v) { return v ? "true" : "false"; }

char lower(char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }

bool iequals_prefix(std::string_view s, std::string_view prefix) {
    if (s.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i)
        if (lower(s[i]) != lower(prefix[i])) return false;
    return true;
}

// Characters that never belong in a path we register for a service: control characters, quotes
// (would break the quoted ImagePath), shell/environment metacharacters, wildcards, forward slash.
bool odd_character(unsigned char c) {
    if (c < 0x20 || c == 0x7F) return true;
    switch (c) {
        case '"': case '%': case '^': case '&': case '|': case '<': case '>': case ';': case '`':
        case '*': case '?': case '/': case '!': case '\'':
            return true;
        default: return false;
    }
}

// Absolute "X:\a\b\c" with plain segments. Returns "" when fine, else a PATH_* code.
const char* shape_problem(std::string_view p) {
    if (p.empty()) return "PATH_UNKNOWN";
    if (p.size() > kDataDirMaxLen) return "PATH_ODD_CHARACTERS";
    for (char ch : p)
        if (odd_character(static_cast<unsigned char>(ch))) return "PATH_ODD_CHARACTERS";
    if (p.size() < 4 || !std::isalpha(static_cast<unsigned char>(p[0])) || p[1] != ':' || p[2] != '\\')
        return "PATH_NOT_ABSOLUTE";
    if (p.find(':', 2) != std::string_view::npos) return "PATH_ODD_CHARACTERS";  // alternate data stream
    std::size_t i = 3;
    while (i <= p.size()) {
        std::size_t j = p.find('\\', i);
        if (j == std::string_view::npos) j = p.size();
        const std::string_view seg = p.substr(i, j - i);
        if (seg.empty() && j != p.size()) return "PATH_NOT_ABSOLUTE";  // "\\" inside the path
        if (seg == "." || seg == "..") return "PATH_NOT_ABSOLUTE";
        if (!seg.empty() && (seg.back() == '.' || seg.back() == ' ')) return "PATH_ODD_CHARACTERS";
        if (j == p.size()) break;
        i = j + 1;
    }
    if (p.back() == '\\') return "PATH_NOT_EXE";
    return "";
}

BinaryPathCheck refuse(const char* code, std::string msg) {
    BinaryPathCheck c;
    c.allowed = false;
    c.code = code;
    c.message = std::move(msg);
    return c;
}

}  // namespace

BinaryPathCheck evaluate_service_binary_path(std::string_view path, const std::vector<std::string>& trusted_roots) {
    if (path.empty()) return refuse("PATH_UNKNOWN", "the location of this meta-sec.exe could not be determined");
    const char* bad = shape_problem(path);
    if (*bad) {
        if (std::string_view(bad) == "PATH_NOT_ABSOLUTE")
            return refuse(bad, "the path of this meta-sec.exe is not a plain absolute drive path");
        if (std::string_view(bad) == "PATH_NOT_EXE")
            return refuse(bad, "the path does not name an executable file");
        if (std::string_view(bad) == "PATH_UNKNOWN") return refuse(bad, "the location of this meta-sec.exe could not be determined");
        return refuse(bad, "the path of this meta-sec.exe contains characters that are not accepted for a service binary");
    }
    if (path.size() < 4 || !iequals_prefix(path.substr(path.size() - 4), ".exe"))
        return refuse("PATH_NOT_EXE", "the path does not name an .exe file");
    for (const std::string& root_in : trusted_roots) {
        std::string root = root_in;
        while (root.size() > 3 && root.back() == '\\') root.pop_back();
        if (*shape_problem(root + "\\x")) continue;  // malformed root: never trusted
        if (root.size() < 4) continue;  // never trust a drive root such as "C:\" (users may write there)
        if (path.size() > root.size() + 1 && iequals_prefix(path, root) && path[root.size()] == '\\') {
            BinaryPathCheck ok;
            ok.allowed = true;
            ok.code = "PATH_OK";
            ok.message = "the binary is inside a protected directory";
            return ok;
        }
    }
    return refuse("PATH_NOT_IN_PROTECTED_LOCATION",
                  "a service runs with its own account's rights, so its binary must be in a directory only administrators can "
                  "write (Program Files or Windows). Copy meta-sec.exe there and run the install from that copy; a user-writable "
                  "binary run as a service would be a privilege escalation");
}

std::string build_service_image_path(std::string_view exe_path) {
    if (*shape_problem(exe_path)) return {};
    return "\"" + std::string(exe_path) + "\" service run --scm";
}

const char* to_string(ServiceChangeStatus s) {
    switch (s) {
        case ServiceChangeStatus::DryRunWouldProceed: return "DRY_RUN_WOULD_PROCEED";
        case ServiceChangeStatus::Done: return "DONE";
        case ServiceChangeStatus::NoOpNotInstalled: return "NO_OP_NOT_INSTALLED";
        case ServiceChangeStatus::RefusedNotElevated: return "REFUSED_NOT_ELEVATED";
        case ServiceChangeStatus::RefusedBadBinaryPath: return "REFUSED_BAD_BINARY_PATH";
        case ServiceChangeStatus::RefusedAlreadyInstalled: return "REFUSED_ALREADY_INSTALLED";
        case ServiceChangeStatus::RefusedNotApproved: return "REFUSED_NOT_APPROVED";
        case ServiceChangeStatus::Failed: return "FAILED";
        case ServiceChangeStatus::Incomplete: return "INCOMPLETE";
    }
    return "FAILED";
}

int service_change_exit_code(ServiceChangeStatus s) {
    switch (s) {
        case ServiceChangeStatus::DryRunWouldProceed:
        case ServiceChangeStatus::Done:
        case ServiceChangeStatus::NoOpNotInstalled: return kExitOk;
        case ServiceChangeStatus::RefusedNotElevated:
        case ServiceChangeStatus::RefusedBadBinaryPath:
        case ServiceChangeStatus::RefusedAlreadyInstalled:
        case ServiceChangeStatus::RefusedNotApproved: return kExitRefused;
        case ServiceChangeStatus::Failed: return kExitError;
        case ServiceChangeStatus::Incomplete: return kExitIncomplete;
    }
    return kExitError;
}

namespace {

BinaryPathCheck full_path_check(const ServiceChangeHooks& h, const std::string& path) {
    const std::vector<std::string> roots = h.trusted_roots();
    BinaryPathCheck c = evaluate_service_binary_path(path, roots);
    if (c.allowed && !h.binary_exposure) {
        // Fail closed: without the exposure look the location is not proven safe.
        c = refuse("PATH_EXPOSURE_UNCHECKED", "the access rules of the binary's location could not be verified");
    } else if (c.allowed) {
        const std::string why = h.binary_exposure(path, roots);
        if (!why.empty())
            c = refuse("PATH_WRITABLE_BY_NON_ADMINS",
                       "the binary or a directory above it can be modified by non-administrators (" + clip(why, 200) +
                           "); a service binary there would be a privilege escalation");
    }
    return c;
}

}  // namespace

ServiceChangeReport run_service_change(const ServiceChangeOptions& opt, const ServiceChangeHooks& h) {
    const bool install = opt.change == ServiceChange::Install;
    ServiceChangeReport rep;
    rep.change = opt.change;
    rep.dry_run = opt.dry_run;
    rep.observed_at_utc = h.now_utc();
    auto finish = [&](ServiceChangeStatus s) {
        rep.status = s;
        rep.finished_at_utc = h.now_utc();
        return rep;
    };

    // Gate 1: Administrator rights. Nothing else is observed or asked without them.
    rep.elevated = h.elevated();
    if (install) {
        // Informational only; it never overrides the elevation decision below.
        rep.binary_path = h.resolve_exe_path();
        rep.path = full_path_check(h, rep.binary_path);
    }
    if (!rep.elevated) return finish(ServiceChangeStatus::RefusedNotElevated);

    // Gate 2: the binary must live in a protected directory (install).
    if (install && !rep.path.allowed) return finish(ServiceChangeStatus::RefusedBadBinaryPath);

    // Gate 3: current state of the service.
    ServiceInfo seen;
    auto observe = [&]() {
        seen = h.query_service();
        rep.service_query_ok = seen.query_ok;
        rep.service_exists = seen.query_ok && seen.install == InstallState::Installed;
        return seen.query_ok;
    };
    if (!observe()) return finish(ServiceChangeStatus::Incomplete);
    if (install && rep.service_exists) return finish(ServiceChangeStatus::RefusedAlreadyInstalled);
    if (!install && !rep.service_exists) return finish(ServiceChangeStatus::NoOpNotInstalled);

    rep.actor = h.actor();
    if (opt.dry_run) return finish(ServiceChangeStatus::DryRunWouldProceed);

    // Gate 4: typed approval on a real console.
    rep.approval_asked = true;
    const std::string shown_image = install ? build_service_image_path(rep.binary_path) : seen.binary_path;
    const std::string shown_account = install ? std::string(kServiceAccountName) : seen.account;
    rep.approval = evaluate_approval(
        h.ask_approval(service_approval_prompt_text(install, rep.actor, rep.elevated, shown_image, shown_account)),
        install ? kServiceInstallPhrase : kServiceUninstallPhrase);
    if (!rep.approval.approved) return finish(ServiceChangeStatus::RefusedNotApproved);
    rep.approved_at_utc = h.now_utc();

    // The human may have taken a while: re-check every precondition before the side effect.
    if (!h.elevated()) return finish(ServiceChangeStatus::RefusedNotElevated);
    if (install) {
        rep.binary_path = h.resolve_exe_path();
        rep.path = full_path_check(h, rep.binary_path);
        if (!rep.path.allowed) return finish(ServiceChangeStatus::RefusedBadBinaryPath);
    }
    if (!observe()) return finish(ServiceChangeStatus::Incomplete);
    if (install && rep.service_exists) return finish(ServiceChangeStatus::RefusedAlreadyInstalled);
    if (!install && !rep.service_exists) return finish(ServiceChangeStatus::NoOpNotInstalled);

    rep.change_attempted = true;
    try {
        rep.outcome = install ? h.install(rep.binary_path) : h.uninstall();
    } catch (const std::exception& e) {
        rep.outcome = {};
        rep.outcome.error_code = "EXCEPTION";
        rep.outcome.detail = e.what();
    }
    const ServiceChangeStatus result = rep.outcome.ok ? ServiceChangeStatus::Done
                                       : rep.outcome.incomplete ? ServiceChangeStatus::Incomplete
                                                                : ServiceChangeStatus::Failed;
    rep.audit_attempted = true;
    try {
        rep.audit_recorded = h.record_audit && h.record_audit(install ? "install" : "uninstall", rep.actor, to_string(result));
    } catch (...) {
        rep.audit_recorded = false;
    }
    return finish(result);
}

namespace {

std::string status_message_core(const ServiceChangeReport& r) {
    const bool install = r.change == ServiceChange::Install;
    switch (r.status) {
        case ServiceChangeStatus::DryRunWouldProceed:
            return install ? "Dry run: every pre-check passes. A real run would ask for typed approval, then register this "
                             "meta-sec.exe as the service. Nothing was changed."
                           : "Dry run: the service exists and would be stopped and removed after typed approval. Nothing was changed.";
        case ServiceChangeStatus::Done:
            return install ? "Service installed (start type: automatic, delayed). It is not started now: it starts at the next boot, "
                             "or run 'sc start MetaSecAgent' from an elevated prompt."
                           : "Service stopped and removed. The data directory and stored events were left on disk; remove them "
                             "yourself if you no longer need the evidence.";
        case ServiceChangeStatus::NoOpNotInstalled: return "The service is not installed; nothing to uninstall.";
        case ServiceChangeStatus::RefusedNotElevated:
            return "Refused: this needs Administrator rights and this process is not elevated. Nothing was asked or changed.";
        case ServiceChangeStatus::RefusedBadBinaryPath: return "Refused: " + r.path.message + ". Nothing was asked or changed.";
        case ServiceChangeStatus::RefusedAlreadyInstalled:
            return "Refused: the service is already installed. Uninstall it first if you want to reinstall. Nothing was changed.";
        case ServiceChangeStatus::RefusedNotApproved:
            return "Refused: approval was not given (" + r.approval.reason + "). Nothing was changed.";
        case ServiceChangeStatus::Failed:
            return std::string(install ? "Install" : "Uninstall") + " failed (" + clip(r.outcome.error_code, 40) + "): " +
                   clip(r.outcome.detail, 200);
        case ServiceChangeStatus::Incomplete:
            if (!r.service_query_ok) return "The Service Control Manager could not be queried; nothing was changed.";
            return std::string(install ? "Install" : "Uninstall") + " is incomplete (" + clip(r.outcome.error_code, 40) + "): " +
                   clip(r.outcome.detail, 200);
    }
    return {};
}

std::string status_message(const ServiceChangeReport& r) {
    std::string m = status_message_core(r);
    if (r.audit_attempted && !r.audit_recorded)
        m += " WARNING: this action could NOT be written to the Windows Event Log (no persistent record was made).";
    return m;
}

}  // namespace

std::string render_service_change_json(const ServiceChangeReport& r, const std::string& version) {
    const bool install = r.change == ServiceChange::Install;
    std::string o = std::format(R"({{"schema_version":{},"command":{},"product":{},"version":{},"mode":"standalone",)",
                                kSchemaVersion, q(install ? "service install" : "service uninstall"), q(kProduct), q(version));
    o += std::format(R"("dry_run":{},"observed_at_utc":{},"finished_at_utc":{},"status":{},"exit_code":{},"message":{},)",
                     b(r.dry_run), q(r.observed_at_utc), q(r.finished_at_utc), q(to_string(r.status)),
                     service_change_exit_code(r.status), q(status_message(r)));
    o += std::format(R"("elevated":{},)", b(r.elevated));
    if (install) {
        o += std::format(R"("binary":{{"path":{},"allowed":{},"code":{},"message":{}}},)", q(redact_binary_path(r.binary_path)),
                         b(r.path.allowed), q(r.path.code), q(clip(r.path.message, 400)));
    }
    o += std::format(R"("service":{{"name":{},"query_ok":{},"exists":{}}},)", q(kServiceName), b(r.service_query_ok),
                     b(r.service_exists));
    o += std::format(R"("approval":{{"required":true,"method":"typed_confirmation_on_console","asked":{},"granted":{},)"
                     R"("reason":{},"actor":{},"approved_at_utc":{}}},)",
                     b(r.approval_asked), b(r.approval.approved), q(r.approval_asked ? r.approval.reason : ""),
                     q(clip(r.actor, 120)), q(r.approved_at_utc));
    o += std::format(R"("change":{{"attempted":{},"ok":{},"error_code":{},"detail":{}}},)", b(r.change_attempted),
                     b(r.outcome.ok), q(clip(r.outcome.error_code, 40)), q(clip(r.outcome.detail, 200)));
    o += std::format(R"("audit_attempted":{},"audit_recorded":{},"audit_sink":"windows_event_log"}})", b(r.audit_attempted),
                     b(r.audit_recorded));
    return o + "\n";
}

std::string render_service_change_text(const ServiceChangeReport& r, const std::string& version) {
    const bool install = r.change == ServiceChange::Install;
    std::string o = std::format("{} v{} | Standalone | Service {}{}\n", kProduct, version, install ? "install" : "uninstall",
                                r.dry_run ? " (DRY RUN)" : "");
    o += std::format("Observed at : {}\n", printable(r.observed_at_utc));
    o += std::format("Elevated    : {}\n", r.elevated ? "yes" : "no");
    if (install) {
        o += std::format("Binary      : {}\n", r.binary_path.empty() ? "(unknown)" : redact_binary_path(r.binary_path));
        o += std::format("Path check  : {} - {}\n", r.path.allowed ? "OK" : "REFUSED", clip(r.path.message, 400));
    }
    o += std::format("Service     : {} - {}\n", kServiceName,
                     !r.service_query_ok ? "unknown (SCM not queried)" : (r.service_exists ? "installed" : "not installed"));
    if (r.approval_asked)
        o += std::format("Approval    : {} ({}), account {}\n", r.approval.approved ? "granted" : "not granted",
                         r.approval.reason, clip(r.actor, 120));
    if (r.audit_attempted)
        o += std::format("Audit log   : {}\n", r.audit_recorded ? "recorded in the Windows Event Log (Application, source MetaSecAgent)"
                                                              : "NOT recorded (Windows Event Log write failed)");
    o += std::format("Result      : {} (exit {})\n", to_string(r.status), service_change_exit_code(r.status));
    o += status_message(r) + "\n";
    return o;
}

}  // namespace metasec
