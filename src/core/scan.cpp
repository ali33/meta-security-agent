#include "scan.hpp"

#include <format>

#include "cli.hpp"
#include "json.hpp"
#include "render.hpp"

namespace metasec {

namespace {

constexpr std::int32_t kHrAccessDenied = static_cast<std::int32_t>(0x80070005u);   // E_ACCESSDENIED
constexpr std::int32_t kWbemAccessDenied = static_cast<std::int32_t>(0x80041003u); // WBEM_E_ACCESS_DENIED

bool is_access_denied(std::int32_t hr) { return hr == kHrAccessDenied || hr == kWbemAccessDenied; }

// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
long long days_from_civil(long long y, unsigned m, unsigned d) {
    y -= m <= 2;
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<long long>(doe) - 719468;
}

bool digits(std::string_view s, std::size_t pos, std::size_t n, int& out) {
    if (pos + n > s.size()) return false;
    int v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const char c = s[pos + i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}

bool is_passive_mode(const std::string& m) {
    return m == "Passive" || m == "Passive mode" || m == "SxS Passive Mode" || m == "EDR Block Mode";
}

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
void put_bool(std::string& o, std::string_view k, bool v) {
    put_str(o, k);
    o += v ? ":true" : ":false";
}
std::string opt_time(const std::optional<long long>& t) { return t ? format_epoch_utc(*t) : std::string(); }

void put_times(std::string& o, const ScanTimes& t) {
    o += '{';
    put_kv(o, "quick_scan_start_utc", opt_time(t.quick_start)); o += ',';
    put_kv(o, "quick_scan_end_utc", opt_time(t.quick_end));
    o += '}';
}

const char* wait_name(WaitEnd w) {
    switch (w) {
        case WaitEnd::Finished: return "finished";
        case WaitEnd::TimedOut: return "timed_out";
        case WaitEnd::Interrupted: return "interrupted";
        case WaitEnd::NoCallResult: return "no_call_result";
    }
    return "finished";
}

std::string printable(std::string_view in) {
    std::string out;
    for (char ch : in) {
        const unsigned char c = static_cast<unsigned char>(ch);
        out += (c < 0x20 || c == 0x7F) ? '?' : static_cast<char>(c);
    }
    return out;
}

}  // namespace

std::optional<long long> parse_cim_datetime(std::string_view s) {
    // yyyymmddHHMMSS.mmmmmm+UUU
    if (s.size() != 25 || s[14] != '.' || (s[21] != '+' && s[21] != '-')) return std::nullopt;
    int y, mo, d, h, mi, se, us, off;
    if (!digits(s, 0, 4, y) || !digits(s, 4, 2, mo) || !digits(s, 6, 2, d) || !digits(s, 8, 2, h) ||
        !digits(s, 10, 2, mi) || !digits(s, 12, 2, se) || !digits(s, 15, 6, us) || !digits(s, 22, 3, off))
        return std::nullopt;
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 59 || off > 840)
        return std::nullopt;
    static constexpr int kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    if (d > kDays[mo - 1] + (mo == 2 && leap ? 1 : 0)) return std::nullopt;
    const long long days = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
    long long t = days * 86400 + h * 3600 + mi * 60 + se;
    t -= (s[21] == '+' ? 1 : -1) * static_cast<long long>(off) * 60;  // local = UTC + offset
    return t;
}

std::string format_epoch_utc(long long epoch_seconds) {
    return format_utc(std::chrono::system_clock::time_point(std::chrono::seconds(epoch_seconds)));
}

ScanGate evaluate_scan_gate(const DefenderScanObservation& def, const AvProductsObservation& av) {
    ScanGate g;
    if (av.obs == Obs::Observed) {
        for (const auto& p : av.products)
            if (av_activity(p.product_state) == AvActivity::On)
                g.protecting_av.push_back(p.name.empty() ? "(unnamed)" : sanitize_for_display(p.name));
    }
    std::string elsewhere;
    if (!g.protecting_av.empty()) {
        elsewhere = " Security Center reports these antivirus products active: ";
        for (std::size_t i = 0; i < g.protecting_av.size(); ++i) elsewhere += (i ? "; " : "") + g.protecting_av[i];
        elsewhere += ". Open that product and run its own scan; META Security Agent cannot command it.";
    } else {
        elsewhere = " No other active antivirus could be identified; use the antivirus you rely on, "
                    "META Security Agent cannot command third-party products.";
    }

    if (def.running_mode) g.running_mode = sanitize_for_display(*def.running_mode);

    if (def.obs == Obs::NotSupported) {
        g.code = "DEFENDER_NOT_SUPPORTED";
        g.message = "Windows Defender management interface is not present on this machine (" + def.error_code + ")." + elsewhere;
        return g;
    }
    if (def.obs != Obs::Observed) {
        g.code = "DEFENDER_UNAVAILABLE";
        g.message = "Defender state could not be read (" + def.error_code + "); refusing to scan blind." + elsewhere;
        return g;
    }
    if (!def.running_mode) {
        g.code = "MODE_MISSING";
        g.message = "Defender did not report AMRunningMode; refusing to scan blind." + elsewhere;
        return g;
    }
    const std::string& m = *def.running_mode;
    if (m == "Normal") {
        g.allowed = true;
        g.code = "DEFENDER_NORMAL";
        g.message = "Defender is the primary antivirus engine (AMRunningMode = Normal).";
        return g;
    }
    if (m == "Not running") {
        g.code = "MODE_NOT_RUNNING";
        g.message = "Defender is not running, so it cannot scan." + elsewhere;
    } else if (is_passive_mode(m)) {
        g.code = "MODE_PASSIVE";
        g.message = "Defender is passive (AMRunningMode = " + g.running_mode + "): another antivirus is the primary engine, "
                    "and a Defender scan would not reflect or replace it." + elsewhere;
    } else {
        g.code = "MODE_UNRECOGNIZED";
        g.message = "Defender reported an unrecognized AMRunningMode (" + g.running_mode + "); refusing." + elsewhere;
    }
    return g;
}

ApprovalDecision evaluate_approval(const ApprovalInput& in) { return evaluate_approval(in, kScanConfirmPhrase); }

ApprovalDecision evaluate_approval(const ApprovalInput& in, std::string_view phrase) {
    // Order matters: every refusal is decided before the typed text is even looked at.
    if (!in.input_is_console) return {false, "NOT_A_CONSOLE"};
    if (!in.output_is_console) return {false, "NO_VISIBLE_PROMPT"};
    switch (in.read) {
        case ReadStatus::Eof: return {false, "EOF"};
        case ReadStatus::Error: return {false, "READ_ERROR"};
        case ReadStatus::Interrupted: return {false, "INTERRUPTED"};
        case ReadStatus::Ok: break;
    }
    // A line-mode console read always ends with the Enter key: require exactly one terminator.
    std::string line = in.line;
    if (line.size() >= 2 && line.compare(line.size() - 2, 2, "\r\n") == 0)
        line.resize(line.size() - 2);
    else if (!line.empty() && line.back() == '\n')
        line.pop_back();
    else
        return {false, "WRONG_CONFIRMATION"};
    if (!phrase.empty() && line == phrase) return {true, "APPROVED"};
    return {false, "WRONG_CONFIRMATION"};
}

std::string approval_prompt_text(const std::string& actor, const std::string& running_mode, bool elevated) {
    std::string o;
    o += "About to start ONE Microsoft Defender QUICK SCAN on this computer.\n";
    o += std::format("  Defender mode : {}\n", printable(running_mode));
    o += std::format("  Approving as  : {}\n", printable(actor));
    o += "  Effect        : Defender scans common locations (can use CPU/disk for several minutes).\n";
    o += "                  Nothing is removed, quarantined or reconfigured by META Security Agent.\n";
    if (!elevated)
        o += "  Note          : this process is not elevated; Windows will probably deny the request.\n";
    o += std::format("To approve, type exactly  {}  and press Enter. Anything else cancels.\n> ", kScanConfirmPhrase);
    return o;
}

const char* to_string(ScanStatus s) {
    switch (s) {
        case ScanStatus::DryRunWouldProceed: return "DRY_RUN_WOULD_PROCEED";
        case ScanStatus::RefusedNotApplicable: return "REFUSED_NOT_APPLICABLE";
        case ScanStatus::RefusedNotApproved: return "REFUSED_NOT_APPROVED";
        case ScanStatus::AccessDenied: return "ACCESS_DENIED";
        case ScanStatus::StartFailed: return "START_FAILED";
        case ScanStatus::Completed: return "COMPLETED";
        case ScanStatus::StartedNotCompleted: return "STARTED_NOT_COMPLETED";
        case ScanStatus::NotConfirmed: return "NOT_CONFIRMED";
    }
    return "NOT_CONFIRMED";
}

int scan_exit_code(ScanStatus s) {
    switch (s) {
        case ScanStatus::DryRunWouldProceed:
        case ScanStatus::Completed: return kExitOk;
        case ScanStatus::RefusedNotApplicable:
        case ScanStatus::RefusedNotApproved: return kExitRefused;
        case ScanStatus::AccessDenied:
        case ScanStatus::StartFailed: return kExitError;
        case ScanStatus::StartedNotCompleted:
        case ScanStatus::NotConfirmed: return kExitIncomplete;
    }
    return kExitError;
}

bool new_scan_visible(const ScanTimes& before, const std::optional<ScanTimes>& after, long long not_before) {
    if (!after || !after->quick_start) return false;
    if (*after->quick_start < not_before - kScanClockSlackSeconds) return false;
    return !before.quick_start || *after->quick_start > *before.quick_start;
}

ScanStatus interpret_scan_outcome(const StartResult& r, const ScanTimes& before,
                                  const std::optional<ScanTimes>& after, long long not_before) {
    if (r.exec_hr < 0) return is_access_denied(r.exec_hr) ? ScanStatus::AccessDenied : ScanStatus::StartFailed;
    if (r.wait == WaitEnd::Finished) {
        if (r.status_hr < 0) return is_access_denied(r.status_hr) ? ScanStatus::AccessDenied : ScanStatus::StartFailed;
        if (r.return_value && *r.return_value != 0) return ScanStatus::StartFailed;
    }
    if (!new_scan_visible(before, after, not_before)) return ScanStatus::NotConfirmed;
    const bool ended = after->quick_end && *after->quick_end >= *after->quick_start;
    if (r.wait == WaitEnd::Finished && ended) return ScanStatus::Completed;
    return ScanStatus::StartedNotCompleted;
}

ScanReport run_scan(const ScanOptions& opt, const ScanHooks& h) {
    ScanReport rep;
    rep.dry_run = opt.dry_run;
    rep.observed_at_utc = h.now_utc();
    rep.elevated = h.elevated();

    const DefenderScanObservation def = h.observe_defender();
    rep.gate = evaluate_scan_gate(def, h.observe_av());
    rep.before = def.times;
    if (!rep.gate.allowed) {
        rep.status = ScanStatus::RefusedNotApplicable;
        rep.finished_at_utc = h.now_utc();
        return rep;
    }
    rep.actor = h.actor();
    if (opt.dry_run) {
        rep.status = ScanStatus::DryRunWouldProceed;
        rep.finished_at_utc = h.now_utc();
        return rep;
    }

    rep.approval_asked = true;
    rep.approval = evaluate_approval(h.ask_approval(approval_prompt_text(rep.actor, rep.gate.running_mode, rep.elevated)));
    if (!rep.approval.approved) {
        rep.status = ScanStatus::RefusedNotApproved;
        rep.finished_at_utc = h.now_utc();
        return rep;
    }
    rep.approved_at_utc = h.now_utc();

    // The human may have taken a while to answer: re-check that the world still allows it, and
    // take the "before" timestamps as late as possible.
    const DefenderScanObservation def2 = h.observe_defender();
    const ScanGate gate2 = evaluate_scan_gate(def2, h.observe_av());
    if (!gate2.allowed) {
        rep.gate = gate2;
        rep.status = ScanStatus::RefusedNotApplicable;
        rep.finished_at_utc = h.now_utc();
        return rep;
    }
    rep.before = def2.times;

    rep.start_attempted = true;
    const long long not_before = h.now_epoch();
    rep.start = h.start_quick_scan(kScanWaitSeconds);
    // A scan may be running now: a failure to re-read must not lose the report.
    try {
        const DefenderScanObservation def3 = h.observe_defender();
        if (def3.obs == Obs::Observed) rep.after = def3.times;
    } catch (...) {
        rep.after.reset();
    }
    rep.new_scan_confirmed = new_scan_visible(rep.before, rep.after, not_before);
    rep.status = interpret_scan_outcome(rep.start, rep.before, rep.after, not_before);
    rep.finished_at_utc = h.now_utc();
    return rep;
}

namespace {

std::string status_message(const ScanReport& r) {
    switch (r.status) {
        case ScanStatus::DryRunWouldProceed:
            return "Dry run: the eligibility gate passes. A real run would ask for typed approval, then start one Defender quick scan. Nothing was started.";
        case ScanStatus::RefusedNotApplicable: return "No scan was started: " + r.gate.message;
        case ScanStatus::RefusedNotApproved:
            return "No scan was started: approval was not given (" + r.approval.reason + ").";
        case ScanStatus::AccessDenied:
            return "Windows denied the request to start the scan (access denied). Run from an elevated prompt or check policy. No scan was started.";
        case ScanStatus::StartFailed: return "Defender reported an error starting the scan. See start.* fields.";
        case ScanStatus::Completed: return "Quick scan completed; Defender timestamps show a new scan.";
        case ScanStatus::StartedNotCompleted:
            return "A new quick scan is visible in Defender but completion was not observed (stopped waiting). The scan is not cancelled by this tool.";
        case ScanStatus::NotConfirmed:
            return "The Start call did not report an error, but no new quick scan is visible in Defender timestamps. Not confirmed.";
    }
    return {};
}

}  // namespace

std::string render_scan_json(const ScanReport& r, const std::string& version) {
    std::string o;
    o += '{';
    o += "\"schema_version\":" + std::to_string(kSchemaVersion) + ',';
    put_kv(o, "command", "scan"); o += ',';
    put_kv(o, "scan_type", "quick"); o += ',';
    put_kv(o, "product", kProduct); o += ',';
    put_kv(o, "version", version); o += ',';
    put_kv(o, "mode", "standalone"); o += ',';
    put_bool(o, "dry_run", r.dry_run); o += ',';
    put_kv(o, "observed_at_utc", r.observed_at_utc); o += ',';
    put_kv(o, "finished_at_utc", r.finished_at_utc); o += ',';
    put_kv(o, "status", to_string(r.status)); o += ',';
    o += "\"exit_code\":" + std::to_string(scan_exit_code(r.status)) + ',';
    put_kv(o, "message", status_message(r)); o += ',';
    o += "\"gate\":{";
    put_bool(o, "allowed", r.gate.allowed); o += ',';
    put_kv(o, "code", r.gate.code); o += ',';
    put_kv(o, "defender_running_mode", r.gate.running_mode); o += ',';
    put_kv(o, "message", r.gate.message); o += ',';
    o += "\"active_antivirus_products\":[";
    for (std::size_t i = 0; i < r.gate.protecting_av.size(); ++i) {
        if (i) o += ',';
        put_str(o, r.gate.protecting_av[i]);
    }
    o += "]},";
    put_bool(o, "elevated", r.elevated); o += ',';
    o += "\"approval\":{";
    put_bool(o, "required", true); o += ',';
    put_kv(o, "method", "typed_confirmation_on_console"); o += ',';
    put_bool(o, "asked", r.approval_asked); o += ',';
    put_bool(o, "granted", r.approval.approved); o += ',';
    put_kv(o, "reason", r.approval_asked ? r.approval.reason : ""); o += ',';
    put_kv(o, "actor", r.actor); o += ',';
    put_kv(o, "approved_at_utc", r.approved_at_utc);
    o += "},\"start\":{";
    put_bool(o, "attempted", r.start_attempted); o += ',';
    put_kv(o, "api", "WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpScan.Start(ScanType=1)"); o += ',';
    put_kv(o, "exec_result", r.start_attempted ? hresult_code(static_cast<std::uint32_t>(r.start.exec_hr)) : ""); o += ',';
    put_kv(o, "completion_result", r.start_attempted ? hresult_code(static_cast<std::uint32_t>(r.start.status_hr)) : ""); o += ',';
    put_kv(o, "return_value", r.start.return_value ? std::to_string(*r.start.return_value) : ""); o += ',';
    put_kv(o, "wait", r.start_attempted ? wait_name(r.start.wait) : "");
    o += "},\"verification\":{\"before\":";
    put_times(o, r.before);
    o += ",\"after\":";
    put_times(o, r.after ? *r.after : ScanTimes{});
    o += ',';
    put_bool(o, "new_scan_confirmed", r.new_scan_confirmed);
    o += "}}\n";
    return o;
}

std::string render_scan_text(const ScanReport& r, const std::string& version) {
    std::string o;
    o += std::format("{} v{} | Standalone | Scan (quick){}\n", kProduct, version, r.dry_run ? " | DRY RUN" : "");
    o += std::format("Observed: {}\n", r.observed_at_utc);
    o += std::format("Gate: {} ({}){}\n", r.gate.allowed ? "ALLOWED" : "REFUSED", r.gate.code,
                     r.gate.running_mode.empty() ? "" : " | Defender mode: " + printable(r.gate.running_mode));
    if (r.approval_asked) {
        o += std::format("Approval: {} ({})\n", r.approval.approved ? "GRANTED" : "NOT GRANTED", r.approval.reason);
        if (r.approval.approved)
            o += std::format("  actor: {} at {}\n", printable(r.actor), r.approved_at_utc);
    }
    if (r.start_attempted) {
        o += std::format("Start: exec {} | completion {} | wait {}\n",
                         hresult_code(static_cast<std::uint32_t>(r.start.exec_hr)),
                         hresult_code(static_cast<std::uint32_t>(r.start.status_hr)), wait_name(r.start.wait));
        o += std::format("Quick scan start/end before: {} / {}\n", opt_time(r.before.quick_start), opt_time(r.before.quick_end));
        if (r.after)
            o += std::format("Quick scan start/end after : {} / {}\n", opt_time(r.after->quick_start), opt_time(r.after->quick_end));
        else
            o += "Quick scan start/end after : (Defender could not be re-read)\n";
    }
    o += std::format("Result: {} (exit {})\n  {}\n", to_string(r.status), scan_exit_code(r.status), status_message(r));
    return o;
}

}  // namespace metasec
