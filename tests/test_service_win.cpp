// Windows integration test for the MVP-4 service host WITHOUT touching the Service Control Manager:
// real named pipe, real SQLite store in a temp directory, real client, fake snapshot hook. Needs no
// Administrator rights, installs nothing, writes only under the temp directory, and terminates on
// Windows Server (all waits are bounded; a hung server fails the test instead of hanging it).
#include <windows.h>

#include <aclapi.h>
#include <objbase.h>
#include <sddl.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "core/ipc_proto.hpp"
#include "core/json.hpp"
#include "core/service_model.hpp"
#include "core/store.hpp"
#include "temp_dir.hpp"
#include "win/datadir_win.hpp"
#include "win/ipc_win.hpp"
#include "win/scm_win.hpp"
#include "win/service_win.hpp"

using namespace metasec;
using namespace metasec::win;
using test_support::TempDir;

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

bool contains(const std::string& s, const std::string& what) { return s.find(what) != std::string::npos; }

std::string random_pipe_name() {
    GUID g{};
    CoCreateGuid(&g);
    char buf[80];
    std::snprintf(buf, sizeof buf, "MetaSecTest-%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X", g.Data1, g.Data2, g.Data3,
                  g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

StatusReport report(int n, State fw) {
    StatusReport r;
    r.hostname = "host";
    r.platform = {"windows", "10.0.1", "client"};
    char t[40];
    std::snprintf(t, sizeof t, "2026-10-30T10:00:%02dZ", n % 60);
    r.observed_at_utc = t;
    CheckResult c;
    c.check_id = "firewall.public";
    c.observed_at_utc = r.observed_at_utc;
    c.state = fw;
    c.source = "fake";
    r.checks.push_back(c);
    return r;
}

// One service stack (observer + pipe + store) running on its own thread, with a scripted snapshot:
// poll 1 sees ENABLED, every later poll DISABLED (a single confirmed change at poll 2 with confirm=1).
class Stack {
public:
    Stack(const std::filesystem::path& dir, DirMode mode, const std::string& pipe, int max_polls, State first = State::Enabled,
          State later = State::Disabled)
        : pipe_(pipe) {
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        done_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        cfg_.data_dir = dir;
        cfg_.dir_mode = mode;
        cfg_.pipe_path = pipe_path(pipe);
        cfg_.pipe_server_sid = current_user_sid_string();
        cfg_.observer.interval_seconds = 1;
        cfg_.observer.confirm_polls = 1;
        cfg_.observer.max_polls = max_polls;
        cfg_.observer.version = "9.9.9";
        cfg_.stop_event = stop_;
        cfg_.snapshot = [this, first, later] {
            const int n = ++snapshots_;
            return report(n, n == 1 ? first : later);
        };
        th_ = std::thread([this] {
            result_ = run_host(cfg_);
            SetEvent(done_);
        });
    }
    ~Stack() {
        if (th_.joinable()) {
            SetEvent(stop_);
            th_.join();
        }
        CloseHandle(stop_);
        CloseHandle(done_);
    }
    // Requests the stop and waits for the host to finish; false if it did not finish in `ms`.
    bool stop_and_join(DWORD ms) {
        SetEvent(stop_);
        const bool ok = WaitForSingleObject(done_, ms) == WAIT_OBJECT_0;
        if (ok && th_.joinable()) th_.join();
        return ok;
    }
    bool wait_done(DWORD ms) { return WaitForSingleObject(done_, ms) == WAIT_OBJECT_0; }
    void join() {
        if (th_.joinable()) th_.join();
    }
    const HostResult& result() const { return result_; }
    IpcClientOptions client() const {
        IpcClientOptions o;
        o.pipe_name = pipe_;
        o.timeout_ms = 6000;
        return o;
    }
    // Polls STATUS until the observer has read `polls` snapshots (bounded).
    bool wait_polls(long long polls, DWORD max_ms = 20000) {
        const ULONGLONG end = GetTickCount64() + max_ms;
        while (GetTickCount64() < end) {
            const IpcSnapshot s = ipc_fetch_status(client());
            if (s.reach == IpcReach::Ok && s.status && s.status->polls >= polls) return true;
            Sleep(100);
        }
        return false;
    }

private:
    std::string pipe_;
    HostConfig cfg_;
    HANDLE stop_ = nullptr, done_ = nullptr;
    std::atomic<int> snapshots_{0};
    std::thread th_;
    HostResult result_;
};

// A client that connects and then says nothing; returns true if the server closed it within `ms`.
bool silent_client_cut_off(const std::wstring& path, DWORD ms, DWORD* elapsed_ms) {
    HANDLE h = INVALID_HANDLE_VALUE;
    const ULONGLONG t0 = GetTickCount64();
    while (GetTickCount64() - t0 < 8000) {
        h = CreateFileW(path.c_str(), kPipeClientAccess, 0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() == ERROR_PIPE_BUSY) WaitNamedPipeW(path.c_str(), 500);
        else break;
    }
    if (h == INVALID_HANDLE_VALUE) return false;
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    OVERLAPPED ov{};
    ov.hEvent = ev;
    char b[16];
    const ULONGLONG start = GetTickCount64();
    bool cut = false;
    if (!ReadFile(h, b, sizeof b, nullptr, &ov)) {
        const DWORD e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ev, ms) == WAIT_OBJECT_0) {
                DWORD n = 0;
                cut = !GetOverlappedResult(h, &ov, &n, FALSE) || n == 0;  // broken pipe (or zero bytes): server hung up, sent nothing
            } else {
                CancelIoEx(h, &ov);
                DWORD n = 0;
                GetOverlappedResult(h, &ov, &n, TRUE);
            }
        } else {
            cut = (e == ERROR_BROKEN_PIPE);
        }
    }
    if (elapsed_ms) *elapsed_ms = static_cast<DWORD>(GetTickCount64() - start);
    CloseHandle(ev);
    CloseHandle(h);
    return cut;
}

// Parses an IPC reply line; returns its error code ("" when ok:true).
std::string error_code_of(const std::string& line) {
    const auto p = json_parse(line.substr(0, line.size() - (line.back() == '\n' ? 1 : 0)));
    if (!p.ok) return "<invalid json>";
    const JsonValue* ok = p.value.find("ok");
    if (ok && ok->boolean) return "";
    const JsonValue* e = p.value.find("error");
    const JsonValue* c = e ? e->find("code") : nullptr;
    return c ? c->string : "<no code>";
}

// ---- SIDs, SDDL, constants ------------------------------------------------------------------

void test_constants_and_sddl() {
    CHECK(std::string(kServiceName) == "MetaSecAgent");
    CHECK(std::wstring(kServiceNameW) == L"MetaSecAgent");
    CHECK(std::string(kDefaultPipeName) == "MetaSecAgent");
    CHECK(pipe_path("MetaSecAgent") == L"\\\\.\\pipe\\MetaSecAgent");
    // the pipe refuses remote clients, detects squatting, and is overlapped; users cannot create instances
    CHECK((kPipePipeMode & PIPE_REJECT_REMOTE_CLIENTS) != 0);
    CHECK((kPipeOpenModeFirst & FILE_FLAG_FIRST_PIPE_INSTANCE) != 0);
    CHECK((kPipeOpenModeNext & FILE_FLAG_FIRST_PIPE_INSTANCE) == 0);
    CHECK((kPipeOpenModeFirst & FILE_FLAG_OVERLAPPED) != 0);
    CHECK((kPipePipeMode & PIPE_TYPE_MESSAGE) == 0);  // byte mode + line protocol
    CHECK((kPipeClientAccess & FILE_APPEND_DATA) == 0);
    CHECK(kPipeMaxInstances >= 1 && kPipeMaxInstances <= 8);
    CHECK(std::wstring(kPipeSddlService) == L"D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;IU)S:(ML;;NW;;;ME)");

    // The service SID is derived like the SCM does: checked against a well-known service.
    CHECK(service_sid_string(L"TrustedInstaller") == L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    const std::wstring svc = service_sid_string(kServiceNameW);
    CHECK(svc.rfind(L"S-1-5-80-", 0) == 0 && svc == service_sid_string(L"metasecagent"));  // case-insensitive name
    CHECK(data_dir_sddl(DirMode::Service) ==
          L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + svc + L")");
    CHECK(data_dir_sddl(DirMode::UserOnly).rfind(L"D:P(A;OICI;FA;;;S-1-5-", 0) == 0);

    for (const std::wstring& s : {std::wstring(kPipeSddlService), data_dir_sddl(DirMode::Service), data_dir_sddl(DirMode::UserOnly)}) {
        PSECURITY_DESCRIPTOR psd = nullptr;
        CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(s.c_str(), SDDL_REVISION_1, &psd, nullptr) != FALSE);
        if (psd) LocalFree(psd);
    }
    CHECK(!service_data_dir().empty() && service_data_dir().filename() == L"MetaSecAgent");
    CHECK(!dev_data_dir().empty() && dev_data_dir().filename() == L"MetaSecAgent-dev");
    CHECK(dev_data_dir() != service_data_dir());

    // ImagePath parsing used by `service status` (quoted and unquoted forms)
    CHECK(image_path_executable("\"C:\\Program Files\\META\\meta-sec.exe\" service run --scm") == "C:\\Program Files\\META\\meta-sec.exe");
    CHECK(image_path_executable("C:\\META\\meta-sec.exe service run --scm") == "C:\\META\\meta-sec.exe");
    // exe location rules on real directories: System32 is protected, a temp directory is not
    const std::vector<std::string> roots = protected_install_roots();
    CHECK(roots.size() >= 2);
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    const std::string notepad = std::string(sysdir) + "\\notepad.exe";
    CHECK(binary_exposure_reason(notepad, roots).empty());
    TempDir t;
    const std::string tmp_exe = (t.dir() / "meta-sec.exe").string();
    CHECK(!binary_exposure_reason(tmp_exe, roots).empty());
    CHECK(canonical_exe_path().size() > 4);
}

// ---- data directory --------------------------------------------------------------------------

std::vector<std::wstring> dacl_sids(const std::filesystem::path& dir, bool* protected_dacl) {
    std::vector<std::wstring> v;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS)
        return v;
    SECURITY_DESCRIPTOR_CONTROL ctrl = 0;
    DWORD rev = 0;
    if (protected_dacl) *protected_dacl = GetSecurityDescriptorControl(sd, &ctrl, &rev) && (ctrl & SE_DACL_PROTECTED);
    for (DWORD i = 0; dacl && i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(dacl, i, &ace)) continue;
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart, &s)) {
            v.push_back(s);
            LocalFree(s);
        }
    }
    LocalFree(sd);
    return v;
}

// Directory junction (no privilege needed): `link` becomes a reparse point to `target`.
bool make_junction(const std::filesystem::path& link, const std::filesystem::path& target) {
    std::error_code ec;
    std::filesystem::create_directory(link, ec);
    HANDLE h = CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    const std::wstring sub = L"\\??\\" + std::filesystem::absolute(target).wstring();
    const std::wstring print = std::filesystem::absolute(target).wstring();
    const USHORT sub_bytes = static_cast<USHORT>(sub.size() * 2), print_bytes = static_cast<USHORT>(print.size() * 2);
    std::vector<BYTE> buf(16 + sub_bytes + 2 + print_bytes + 2, 0);
    auto put16 = [&](std::size_t at, USHORT v) { std::memcpy(&buf[at], &v, 2); };
    const DWORD tag = 0xA0000003;  // IO_REPARSE_TAG_MOUNT_POINT
    std::memcpy(&buf[0], &tag, 4);
    put16(4, static_cast<USHORT>(buf.size() - 8));
    put16(8, 0);
    put16(10, sub_bytes);
    put16(12, static_cast<USHORT>(sub_bytes + 2));
    put16(14, print_bytes);
    std::memcpy(&buf[16], sub.data(), sub_bytes);
    std::memcpy(&buf[16 + sub_bytes + 2], print.data(), print_bytes);
    DWORD ret = 0;
    const BOOL ok = DeviceIoControl(h, 0x000900A4 /* FSCTL_SET_REPARSE_POINT */, buf.data(), static_cast<DWORD>(buf.size()), nullptr, 0, &ret, nullptr);
    CloseHandle(h);
    return ok != FALSE;
}

struct JunctionGuard {  // removes the link itself (never its target) before the TempDir goes away
    std::filesystem::path link;
    ~JunctionGuard() { RemoveDirectoryW(link.c_str()); }
};

void test_data_dir() {
    const std::wstring me = current_user_sid_string();  // the test account is neither SYSTEM, Administrators nor the service
    TempDir t;
    {  // UserOnly: created with a protected DACL naming only the user, SYSTEM and Administrators
        const auto d = t.dir() / "dev";
        const DirCheck c = prepare_data_dir(d, DirMode::UserOnly);
        CHECK(c.ok && c.created && c.dacl_reapplied);
        bool prot = false;
        const auto sids = dacl_sids(d, &prot);
        CHECK(prot && sids.size() == 3);
        for (const auto& s : sids) CHECK(s == L"S-1-5-18" || s == L"S-1-5-32-544" || s == current_user_sid_string());
        const DirCheck again = prepare_data_dir(d, DirMode::UserOnly);  // every start: idempotent
        CHECK(again.ok && !again.created);
        // the store can live there
        StoreOpen so = EventStore::open(d / "events.db");
        CHECK(so.ok);
    }
    {  // Service rules: SYSTEM, Administrators, service SID only (no Users, no Everyone), inheritable
        const auto d = t.dir() / "svc";  // `me` stands in for the installer (Administrators) in this unprivileged test
        const DirCheck c = prepare_data_dir(d, DirMode::Service, me);
        CHECK(c.ok && c.created);
        bool prot = false;
        const auto sids = dacl_sids(d, &prot);
        CHECK(prot && sids.size() == 4);
        for (const auto& s : sids)
            CHECK(s == L"S-1-5-18" || s == L"S-1-5-32-544" || s == service_sid_string(kServiceNameW) || s == me);
        for (const auto& s : sids) CHECK(s != L"S-1-1-0" && s != L"S-1-5-32-545" && s != L"S-1-5-11");
        CHECK(prepare_data_dir(d, DirMode::Service, me).ok);  // re-apply + verify on every start
    }
    {  // a junction is refused, not followed
        const auto real = t.dir() / "real";
        std::filesystem::create_directories(real);
        const auto link = t.dir() / "link";
        JunctionGuard g{link};
        CHECK(make_junction(link, real));
        for (DirMode m : {DirMode::UserOnly, DirMode::Service}) {
            const DirCheck c = prepare_data_dir(link, m, me);
            CHECK(!c.ok && contains(c.error, "reparse point"));
        }
        // Service mode also refuses a path that merely PASSES THROUGH a junction
        CHECK(prepare_data_dir(real / "svc2", DirMode::Service, me).ok);
        const DirCheck via = prepare_data_dir(link / "svc2", DirMode::Service, me);
        CHECK(!via.ok && contains(via.error, "reparse point"));
    }
    {  // Service mode: a PRE-EXISTING directory owned by the invoking account (not SYSTEM/Administrators/service) is refused
        const auto d = t.dir() / "pre";
        CHECK(prepare_data_dir(d, DirMode::UserOnly).ok);  // owner: this account
        const DirCheck c = prepare_data_dir(d, DirMode::Service);
        CHECK(!c.ok && contains(c.error, "untrusted account"));
    }
    {  // Service mode: children must be plain files; hard links, sub-directories and reparse points are refused
        const auto d = t.dir() / "kids";
        CHECK(prepare_data_dir(d, DirMode::Service, me).ok);
        std::FILE* f = nullptr;
        _wfopen_s(&f, (d / "events.db").c_str(), L"wb");
        if (f) std::fclose(f);
        CHECK(prepare_data_dir(d, DirMode::Service, me).ok);  // a normal store file is fine
        CHECK(CreateHardLinkW((d / "alias").c_str(), (d / "events.db").c_str(), nullptr) != FALSE);
        DirCheck c = prepare_data_dir(d, DirMode::Service, me);
        CHECK(!c.ok && contains(c.error, "hard-linked"));
        DeleteFileW((d / "alias").c_str());
        CHECK(prepare_data_dir(d, DirMode::Service, me).ok);
        std::filesystem::create_directory(d / "sub");
        c = prepare_data_dir(d, DirMode::Service, me);
        CHECK(!c.ok && contains(c.error, "sub-directory"));
        RemoveDirectoryW((d / "sub").c_str());
        const auto target = t.dir() / "jt";
        std::filesystem::create_directories(target);
        JunctionGuard g{d / "j"};
        CHECK(make_junction(d / "j", target));
        c = prepare_data_dir(d, DirMode::Service, me);
        CHECK(!c.ok && contains(c.error, "reparse point"));
    }
    {  // UNC / device paths are never used
        CHECK(!prepare_data_dir(L"\\\\server\\share\\x", DirMode::UserOnly).ok);
        CHECK(!prepare_data_dir(L"\\\\?\\C:\\x", DirMode::Service).ok);
        CHECK(!prepare_data_dir(L"\\\\.\\C:\\x", DirMode::UserOnly).ok);
    }
    {  // not absolute / empty
        CHECK(!prepare_data_dir("relative\\dir", DirMode::UserOnly).ok);
        CHECK(!prepare_data_dir("", DirMode::Service).ok);
    }
    {  // a development directory that already holds files is left alone (its rules are not rewritten)
        const auto d = t.dir() / "existing";
        std::filesystem::create_directories(d);
        std::FILE* f = nullptr;
        _wfopen_s(&f, (d / "keep.txt").c_str(), L"wb");
        if (f) std::fclose(f);
        const DirCheck c = prepare_data_dir(d, DirMode::UserOnly);
        CHECK(c.ok && !c.created && !c.dacl_reapplied);
    }
}

// ---- pipe + store end to end ------------------------------------------------------------------

void test_round_trip_and_hostile_clients() {
    TempDir t;
    const auto dir = t.dir() / "data";
    const std::string pipe = random_pipe_name();
    Stack s(dir, DirMode::UserOnly, pipe, /*max_polls=*/0);
    CHECK(s.wait_polls(3));

    // STATUS / HEALTH / EVENTS over the real pipe, parsed by the real client code
    const IpcSnapshot st = ipc_fetch_status(s.client());
    CHECK(st.reach == IpcReach::Ok && st.status.has_value());
    if (st.status) {
        CHECK(st.status->state == ObserverState::Running);
        CHECK(st.status->polls >= 3 && st.status->version == "9.9.9");
        CHECK(st.status->store_errors == 0 && st.status->snapshot_errors == 0);
        CHECK(st.status->events_total >= 2);  // service_started + the change
    }
    {
        const IpcRawReply h = ipc_call(s.client(), render_request({IpcVerb::Health, 0}));
        CHECK(h.reach == IpcReach::Ok);
        const IpcParsedResponse p = parse_response(h.line, IpcVerb::Health);
        CHECK(p.valid && p.response.ok && p.response.health && p.response.health->health == "OK");
    }
    {
        const ServiceEventsReport ev = ipc_fetch_events(s.client(), 50, "2026-10-30T10:00:00Z");
        CHECK(ev.reach == IpcReach::Ok && ev.data.has_value());
        int changes = 0, started = 0;
        if (ev.data)
            for (const auto& e : ev.data->events) {
                if (e.kind == "change" && e.check_id == "firewall.public" && e.from_state == "ENABLED" && e.to_state == "DISABLED") ++changes;
                if (e.kind == kLifecycleStarted) ++started;
            }
        CHECK(changes == 1 && started == 1);
        const ServiceEventsReport one = ipc_fetch_events(s.client(), 1, "x");
        CHECK(one.reach == IpcReach::Ok && one.data && one.data->events.size() == 1);
    }

    // malformed / oversize / unknown / lowercase requests get a typed error, never a crash or a hang
    struct Bad {
        std::string bytes;
        const char* code;
    };
    const std::vector<Bad> bad = {
        {"status\n", "UNKNOWN_COMMAND"},
        {"Status\n", "UNKNOWN_COMMAND"},
        {"SCAN QUICK\n", "UNKNOWN_COMMAND"},
        {"STATUS extra\n", "EXTRA_TOKENS"},
        {"STATUS  \n", "EXTRA_TOKENS"},
        {"EVENTS 0\n", "BAD_ARGUMENT"},
        {"EVENTS 201\n", "BAD_ARGUMENT"},
        {"EVENTS abc\n", "BAD_ARGUMENT"},
        {"\n", "EMPTY_REQUEST"},
        {std::string("STATUS\0\n", 8), "EMBEDDED_NUL"},
        {"STATUS\x01\n", "CONTROL_CHARACTER"},
        {"STAT\xC3\x9C" "S\n", "NON_ASCII"},
        {std::string(200, 'A') + "\n", "REQUEST_TOO_LONG"},
        {std::string(10 * 1024, 'A'), "REQUEST_TOO_LONG"},                 // 10 KB, no newline at all
        {std::string(10 * 1024, 'A') + "\n", "REQUEST_TOO_LONG"},
    };
    for (const Bad& b : bad) {
        const IpcRawReply r = ipc_call(s.client(), b.bytes);
        CHECK(r.reach == IpcReach::Ok);
        if (r.reach == IpcReach::Ok) {
            const std::string code = error_code_of(r.line);
            if (code != b.code) std::fprintf(stderr, "  request %zu bytes: expected %s got %s\n", b.bytes.size(), b.code, code.c_str());
            CHECK(code == b.code || (std::string(b.code) == "REQUEST_TOO_LONG" && code == "NO_NEWLINE"));
        }
        CHECK(r.line.size() <= kIpcMaxResponseBytes);
    }
    // pipelined garbage after the first newline is ignored; the first line is what counts
    {
        const IpcRawReply r = ipc_call(s.client(), "STATUS\nSCAN\nSTATUS\n");
        CHECK(r.reach == IpcReach::Ok && error_code_of(r.line).empty());
    }

    // A silent client is cut off by the read timeout; a flood of silent clients (all instances)
    // does not stop the observer, and a valid request is served once they are gone.
    const long long polls_before = s.result().observer.polls;  // (not final yet; informational)
    (void)polls_before;
    const IpcSnapshot before = ipc_fetch_status(s.client());
    DWORD elapsed = 0;
    CHECK(silent_client_cut_off(pipe_path(pipe), 8000, &elapsed));
    CHECK(elapsed >= 150 && elapsed < 2000);  // request deadline is 500 ms (250 ms on the reserved instance): neither instant nor unbounded
    {
        std::vector<std::thread> silent;
        std::atomic<int> cut{0};
        const int kSilent = kPipeMaxInstances + 2;  // more silent connections than instances
        const ULONGLONG flood_start = GetTickCount64();
        for (int i = 0; i < kSilent; ++i)
            silent.emplace_back([&] {
                if (silent_client_cut_off(pipe_path(pipe), 8000, nullptr)) ++cut;
            });
        Sleep(300);  // all instances are now held by silent clients
        const IpcSnapshot during = ipc_fetch_status(s.client());  // waits for a free instance (bounded), then succeeds
        CHECK(during.reach == IpcReach::Ok);
        for (auto& th : silent) th.join();
        CHECK(cut == kSilent);
        CHECK(GetTickCount64() - flood_start < 5000);  // two waves of 500 ms plus slack, not 2 s each
    }
    // 10 KB written slowly... or a client that sends a partial line and stalls
    {
        const IpcClientOptions o = s.client();
        HANDLE h = CreateFileW(pipe_path(pipe).c_str(), kPipeClientAccess, 0, nullptr, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        CHECK(h != INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(h, "STAT", 4, &w, nullptr);  // no newline, then silence
            CloseHandle(h);                         // abrupt close mid-request
        }
        (void)o;
    }
    const IpcSnapshot after = ipc_fetch_status(s.client());
    CHECK(after.reach == IpcReach::Ok && after.status && before.status && after.status->polls > before.status->polls);  // observer never stalled

    // The pipe's DACL: deny network, no right to create instances for anyone but SYSTEM, Administrators and the server itself
    {
        HANDLE h = CreateFileW(pipe_path(pipe).c_str(), kPipeClientAccess | READ_CONTROL, 0, nullptr, OPEN_EXISTING,
                               SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        CHECK(h != INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE) {
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            CHECK(GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) == ERROR_SUCCESS);
            bool deny_network = false;
            bool no_one_else_creates = true;
            for (DWORD i = 0; dacl && i < dacl->AceCount; ++i) {
                void* ace = nullptr;
                GetAce(dacl, i, &ace);
                const ACE_HEADER* hdr = static_cast<ACE_HEADER*>(ace);
                LPWSTR sid = nullptr;
                ConvertSidToStringSidW(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart, &sid);
                const std::wstring ss = sid ? sid : L"";
                if (sid) LocalFree(sid);
                if (hdr->AceType == ACCESS_DENIED_ACE_TYPE && ss == L"S-1-5-2") deny_network = true;
                if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE && ss != L"S-1-5-18" && ss != L"S-1-5-32-544" && ss != current_user_sid_string() &&
                    (static_cast<ACCESS_ALLOWED_ACE*>(ace)->Mask & FILE_APPEND_DATA))
                    no_one_else_creates = false;
                CHECK(ss != L"S-1-1-0" && ss != L"S-1-5-7");  // Everyone / Anonymous never appear
            }
            CHECK(deny_network && no_one_else_creates);
            if (sd) LocalFree(sd);
            CloseHandle(h);
        }
    }

    // Squatting: a second server on the same name cannot start (FILE_FLAG_FIRST_PIPE_INSTANCE)
    {
        IpcServer::Config cfg;
        cfg.pipe_path = pipe_path(pipe);
        cfg.server_sid = current_user_sid_string();
        IpcServer::Hooks hk;
        hk.status = [] { return ObserverStatus{}; };
        hk.recent_events = [](int) { return StoreResult<std::vector<StoredEvent>>{}; };
        IpcServer second(cfg, hk);
        std::string err;
        CHECK(!second.start(err) && contains(err, "already in use"));
    }
    // Server identity check on the client side
    {
        IpcClientOptions o = s.client();
        o.verify_server = [](DWORD) { return false; };
        const IpcSnapshot sn = ipc_fetch_status(o);
        CHECK(sn.reach == IpcReach::InvalidReply && sn.reason == "PIPE_SERVER_NOT_SERVICE");
        o.verify_server = [](DWORD pid) { return pid == GetCurrentProcessId(); };
        CHECK(ipc_fetch_status(o).reach == IpcReach::Ok);
    }

    // Deterministic stop
    const ULONGLONG t0 = GetTickCount64();
    CHECK(s.stop_and_join(8000));
    CHECK(GetTickCount64() - t0 < 6000);
    const HostResult& r = s.result();
    CHECK(r.store_ok && r.pipe_ok && r.observer.stop == ObserverStop::Interrupted);
    CHECK(r.pipe_instances == kPipeMaxInstances);  // every instance could be created (CREATE_PIPE_INSTANCE for the server itself)
    CHECK(r.observer.polls >= 4);
    CHECK(r.ipc.connections > 20 && r.ipc.rejected >= 10 && r.ipc.timeouts >= 5 && r.ipc.served >= 5);
    CHECK(r.final_status.state == ObserverState::Stopped);
    // the pipe is gone after stop
    CHECK(ipc_fetch_status(s.client()).reach == IpcReach::Unreachable);
}

void test_restart_persistence() {
    TempDir t;
    const auto dir = t.dir() / "data";
    {
        Stack a(dir, DirMode::UserOnly, random_pipe_name(), /*max_polls=*/3);
        CHECK(a.wait_done(30000));
        a.join();
        CHECK(a.result().store_ok && a.result().observer.stop == ObserverStop::MaxPolls && a.result().observer.polls == 3);
    }
    {
        // Second run in the same directory: sees the first run's events, adds none for the unchanged state
        // (the persisted checkpoint is the baseline; events are never replayed).
        const std::string pipe = random_pipe_name();
        Stack b(dir, DirMode::UserOnly, pipe, /*max_polls=*/0, State::Disabled, State::Disabled);
        CHECK(b.wait_polls(2));
        const ServiceEventsReport ev = ipc_fetch_events(b.client(), 50, "x");
        CHECK(ev.reach == IpcReach::Ok && ev.data);
        if (ev.data) {
            int changes = 0, started = 0, stopped = 0;
            for (const auto& e : ev.data->events) {
                if (e.kind == "change") ++changes;
                if (e.kind == kLifecycleStarted) ++started;
                if (e.kind == kLifecycleStopped) ++stopped;
            }
            CHECK(changes == 1);            // from run 1, not duplicated
            CHECK(started == 2 && stopped == 1);
        }
        CHECK(b.stop_and_join(8000));
    }
    StoreOpen so = EventStore::open(dir / "events.db");
    CHECK(so.ok);
    if (so.ok) {
        int changes = 0, started = 0, stopped = 0;
        for (const auto& e : so.store->recent_events(500).value) {
            if (e.kind == "change") ++changes;
            if (e.kind == kLifecycleStarted) ++started;
            if (e.kind == kLifecycleStopped) ++stopped;
        }
        CHECK(changes == 1 && started == 2 && stopped == 2);
    }
}

void test_degraded_but_alive() {
    // A data directory that is a junction: the store is refused (fail closed), the service keeps
    // observing and keeps the pipe so `service status` can say what is wrong. No crash loop.
    TempDir t;
    const auto real = t.dir() / "real";
    std::filesystem::create_directories(real);
    const auto link = t.dir() / "link";
    JunctionGuard g{link};
    CHECK(make_junction(link, real));
    Stack s(link, DirMode::UserOnly, random_pipe_name(), /*max_polls=*/0);
    CHECK(s.wait_polls(2));
    const IpcSnapshot st = ipc_fetch_status(s.client());
    CHECK(st.reach == IpcReach::Ok && st.status);
    if (st.status) {
        CHECK(st.status->store_errors > 0 && contains(st.status->last_error, "reparse point"));
        CHECK(st.status->polls >= 2);
    }
    const ServiceEventsReport ev = ipc_fetch_events(s.client(), 10, "x");
    CHECK(ev.reach != IpcReach::Ok);  // typed refusal (STORE_UNAVAILABLE), not a crash
    CHECK(s.stop_and_join(8000));
    CHECK(!s.result().store_ok && s.result().pipe_ok);
    CHECK(!std::filesystem::exists(real / "events.db"));  // nothing was written through the junction
}

void test_client_failures() {
    IpcClientOptions o;
    o.pipe_name = random_pipe_name();
    o.timeout_ms = 1000;
    const IpcSnapshot s = ipc_fetch_status(o);
    CHECK(s.reach == IpcReach::Unreachable && contains(s.reason, "not found"));
    const ServiceEventsReport e = ipc_fetch_events(o, 5, "x");
    CHECK(e.reach == IpcReach::Unreachable && service_events_exit_code(e) == 3);
    // SCM view works without privileges and without the service installed (CI and dev machines)
    DWORD pid = 99;
    const ServiceInfo info = query_service_info(&pid);
    CHECK(info.query_ok);
    CHECK(info.install == InstallState::Installed || pid == 0);  // not installed (CI, dev): no process id
}

}  // namespace

int main() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    test_constants_and_sddl();
    test_data_dir();
    test_client_failures();
    test_round_trip_and_hostile_clients();
    test_restart_persistence();
    test_degraded_but_alive();
    std::printf("%d checks, %d failed\n", g_checks, g_failed);
    CoUninitialize();
    return g_failed == 0 ? 0 : 1;
}
