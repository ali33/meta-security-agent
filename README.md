# META Security Agent

Open-source **C++20**, **standalone-first**, **console-first** endpoint security auditing and management toolkit.

**Status: MVP-0 (`status`), MVP-1 (`audit`), MVP-2 (`watch`) and MVP-3 (`scan --quick`), and MVP-4 (`service`) prototype. Not a replacement for antivirus/EDR. Not production-ready.**

## Goals
- **Run first:** a single `meta-sec.exe` gives real Windows security observations locally without network, Center or database.
- **Standalone by default:** Center enrollment is optional; loss of Center never disables local security checks.
- **Console first:** Agent CLI -> local Windows Service -> optional Center connector -> Center CLI -> web UI.
- **Incremental MVP:** each milestone produces a runnable, visible demo, tests, acceptance criteria and rollback.
- **Safe by default:** read-only, deny-by-default, per-agent identity, least privilege, explicit human approval for side effects.

## Build and test (Windows x64)
Requirements: Visual Studio 2022 (MSVC, C++ desktop workload) and CMake >= 3.20. Only third-party code: SQLite (public domain) vendored in `third_party/sqlite`; the build needs no network.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\meta-sec.exe --help
.\build\Release\meta-sec.exe status
.\build\Release\meta-sec.exe status --json
.\build\Release\meta-sec.exe audit
.\build\Release\meta-sec.exe audit --json
.\build\Release\meta-sec.exe watch --interval 5 --max-polls 12   # Ctrl+C stops earlier
.\build\Release\meta-sec.exe watch --json
.\build\Release\meta-sec.exe scan --quick --dry-run     # checks eligibility, starts nothing
.\build\Release\meta-sec.exe scan --quick               # asks you to type a confirmation first
```

`meta-sec status` is read-only and offline. It reports the host name, Windows version, Windows Firewall profile states (`INetFwPolicy2`), the aggregate Windows Security Center antivirus health (`WscGetSecurityProviderHealth`) and Microsoft Defender specific state (WMI `MSFT_MpComputerStatus`: antivirus and real-time protection enabled). WSC health and Defender state are separate checks on purpose: another AV product can make WSC `GOOD` while Defender is `PASSIVE` (not the primary engine). A call that fails is reported as `UNKNOWN` or `NOT_SUPPORTED`, never as a positive state, and the overall result is then `INCOMPLETE` (exit code 3). The overall value summarises the observation; it is not an antivirus protection verdict. Not yet implemented: detections.

`meta-sec audit` judges those observations (and the antivirus products registered with Security Center, read from WMI `ROOT\SecurityCenter2`) against seven versioned rules (`META-FW-001..003`, `META-AV-001..004`). Each rule returns `PASS`, `FAIL`, `UNKNOWN` or `NOT_APPLICABLE` with severity, remediation text, evidence and data-source provenance; `UNKNOWN` is never turned into `PASS`. Exit code: `0` nothing failed and nothing unknown, `1` at least one confirmed `FAIL` (outranks `3`), `3` no failure but some rule could not be decided, `2` error. Signature freshness is judged only from Defender when it is the primary engine (threshold 3 days). Audit never changes a setting. See [docs/CLI.md](docs/CLI.md).

`meta-sec watch` polls the same read-only checks (default every 30 s) and prints a one-time baseline, then **one line per confirmed change** of a check's state, timestamped, with the old and new state and evidence; `--json` gives NDJSON. A change must be seen on 2 consecutive polls (`--confirm`) before it is reported, so flapping and one-off read errors stay quiet, and a check that merely becomes unreadable is reported as `observation_lost`, never as "turned off". Nothing is replayed, stored or sent anywhere. Stop with Ctrl+C or `--max-polls N`. Exit `0`, or `3` if the last poll was incomplete, `2` on error. Detection logic is verified with injected fake snapshots; it has **not** been verified against a real setting change on a lab machine. See [docs/CLI.md](docs/CLI.md).

`meta-sec scan --quick` is the first command with a side effect: it starts **one Microsoft Defender quick scan**, and nothing else (no full/custom scan, no remediation, no quarantine, no setting change). It runs only when (1) Defender is the primary engine (`AMRunningMode` exactly `Normal`; passive, not running or unreadable is **refused** and the antivirus that is actually active is named, because Windows has no common interface to command a third-party antivirus) and (2) a human types `START QUICK SCAN` on a real console: if stdin is not a console (pipe, file, `NUL`) or stderr is redirected, it refuses without prompting. There is no flag that skips the approval. The approving Windows account and time are recorded in the output. `--dry-run` shows what would happen and starts nothing. Exit `0` completed (a new scan is visible in Defender's own timestamps), `4` refused (not applicable or not approved), `3` not confirmed or still running when we stopped waiting, `2` error (including access denied). **Verified on a Windows 11 machine only for the refusal paths** (Defender not running, non-admin); a real scan has **not** been run on a machine where Defender is the primary engine. See [docs/CLI.md](docs/CLI.md) and [docs/SECURITY.md](docs/SECURITY.md).

`meta-sec service ...` (MVP-4) adds an optional background observer: the same `meta-sec.exe` runs as a Windows service (`NT AUTHORITY\LocalService`), polls the status checks with the `watch` logic and stores confirmed changes in a local SQLite database under `%ProgramData%\MetaSecAgent` (ACL: SYSTEM/Administrators/service only; capped at 10,000 rows / 16 MiB, oldest rotated out). `service status [--json]` and `service events [--limit N]` read it through a read-only local named pipe (allowlist STATUS/HEALTH/EVENTS, no remote clients), so no elevation is needed to look; with no service installed they say so plainly (exit 0) and `status`/`audit`/`watch`/`scan` keep working standalone. `service install|uninstall` need Administrator rights, a binary under Program Files or Windows, and a typed confirmation on a real console (else exit 4); `--dry-run` shows the plan. `service run --console` runs the observer in the foreground. **Verified here only without admin: foreground observer, store, pipe, status/refusals. Installing the service, running under the Service Control Manager and surviving a reboot were NOT tested.** See [docs/CLI.md](docs/CLI.md), [docs/SECURITY.md](docs/SECURITY.md).

Evidence from a real machine: [MVP-0](docs/evidence/mvp0-win11.md), [MVP-1](docs/evidence/mvp1-win11.md), [MVP-2](docs/evidence/mvp2-win11.md), [MVP-3](docs/evidence/mvp3-win11.md), [MVP-4](docs/evidence/mvp4-win11.md). Windows Server has not been tested.


## Start here
- [Developer handoff — scope, architecture, goals, gates, test plan](docs/HANDOFF.md)
- [Roadmap MVP 0–9](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security baseline](docs/SECURITY.md)
- [CLI contract](docs/CLI.md)
- [Acceptance criteria](docs/ACCEPTANCE.md)

## License
MIT for original project code. Third-party components retain their respective licenses.
