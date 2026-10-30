# META Security Agent

Open-source **C++20**, **standalone-first**, **console-first** endpoint security auditing and management toolkit.

**Status: MVP-0 source prototype. Not a replacement for antivirus/EDR. Not production-ready.**

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
```

`meta-sec status` is read-only and offline. It reports the host name, Windows version, Windows Firewall profile states (`INetFwPolicy2`), the aggregate Windows Security Center antivirus health (`WscGetSecurityProviderHealth`) and Microsoft Defender specific state (WMI `MSFT_MpComputerStatus`: antivirus and real-time protection enabled). WSC health and Defender state are separate checks on purpose: another AV product can make WSC `GOOD` while Defender is `PASSIVE` (not the primary engine). A call that fails is reported as `UNKNOWN` or `NOT_SUPPORTED`, never as a positive state, and the overall result is then `INCOMPLETE` (exit code 3). The overall value summarises the observation; it is not an antivirus protection verdict. Not yet implemented: signature freshness judgement, detections, audit rules.

Evidence from a real machine: [docs/evidence/mvp0-win11.md](docs/evidence/mvp0-win11.md). Windows Server has not been tested.

## Start here
- [Developer handoff — scope, architecture, goals, gates, test plan](docs/HANDOFF.md)
- [Roadmap MVP 0–9](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security baseline](docs/SECURITY.md)
- [CLI contract](docs/CLI.md)
- [Acceptance criteria](docs/ACCEPTANCE.md)

## License
MIT for original project code. Third-party components retain their respective licenses.
