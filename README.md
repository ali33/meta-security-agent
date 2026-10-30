# META Security Agent

Open-source **C++20**, **standalone-first**, **console-first** endpoint security auditing and management toolkit.

**Status: MVP-0 (`status`) and MVP-1 (`audit`) prototype. Not a replacement for antivirus/EDR. Not production-ready.**

## Goals
- **Run first:** a single `meta-sec.exe` gives real Windows security observations locally without network, Center or database.
- **Standalone by default:** Center enrollment is optional; loss of Center never disables local security checks.
- **Console first:** Agent CLI -> local Windows Service -> optional Center connector -> Center CLI -> web UI.
- **Incremental MVP:** each milestone produces a runnable, visible demo, tests, acceptance criteria and rollback.
- **Safe by default:** read-only, deny-by-default, per-agent identity, least privilege, explicit human approval for side effects.

## Build and test (Windows x64)
Requirements: Visual Studio 2022 (MSVC, C++ desktop workload) and CMake >= 3.20. No third-party libraries.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\meta-sec.exe --help
.\build\Release\meta-sec.exe status
.\build\Release\meta-sec.exe status --json
.\build\Release\meta-sec.exe audit
.\build\Release\meta-sec.exe audit --json
```

`meta-sec status` is read-only and offline. It reports the host name, Windows version, Windows Firewall profile states (`INetFwPolicy2`), the aggregate Windows Security Center antivirus health (`WscGetSecurityProviderHealth`) and Microsoft Defender specific state (WMI `MSFT_MpComputerStatus`: antivirus and real-time protection enabled). WSC health and Defender state are separate checks on purpose: another AV product can make WSC `GOOD` while Defender is `PASSIVE` (not the primary engine). A call that fails is reported as `UNKNOWN` or `NOT_SUPPORTED`, never as a positive state, and the overall result is then `INCOMPLETE` (exit code 3). The overall value summarises the observation; it is not an antivirus protection verdict. Not yet implemented: detections, change watching, scanning.

`meta-sec audit` judges those observations (and the antivirus products registered with Security Center, read from WMI `ROOT\SecurityCenter2`) against seven versioned rules (`META-FW-001..003`, `META-AV-001..004`). Each rule returns `PASS`, `FAIL`, `UNKNOWN` or `NOT_APPLICABLE` with severity, remediation text, evidence and data-source provenance; `UNKNOWN` is never turned into `PASS`. Exit code: `0` nothing failed and nothing unknown, `1` at least one confirmed `FAIL` (outranks `3`), `3` no failure but some rule could not be decided, `2` error. Signature freshness is judged only from Defender when it is the primary engine (threshold 3 days). Audit never changes a setting. See [docs/CLI.md](docs/CLI.md).

Evidence from a real machine: [MVP-0](docs/evidence/mvp0-win11.md), [MVP-1](docs/evidence/mvp1-win11.md). Windows Server has not been tested.


## Start here
- [Developer handoff — scope, architecture, goals, gates, test plan](docs/HANDOFF.md)
- [Roadmap MVP 0–9](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security baseline](docs/SECURITY.md)
- [CLI contract](docs/CLI.md)
- [Acceptance criteria](docs/ACCEPTANCE.md)

## License
MIT for original project code. Third-party components retain their respective licenses.
