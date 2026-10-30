# META Security Agent

Open-source **C++20**, **standalone-first**, **console-first** endpoint security auditing and management toolkit.

**Status: MVP-0 source prototype. Not a replacement for antivirus/EDR. Not production-ready.**

## Goals
- **Run first:** a single `meta-sec.exe` gives real Windows security observations locally without network, Center or database.
- **Standalone by default:** Center enrollment is optional; loss of Center never disables local security checks.
- **Console first:** Agent CLI -> local Windows Service -> optional Center connector -> Center CLI -> web UI.
- **Incremental MVP:** each milestone produces a runnable, visible demo, tests, acceptance criteria and rollback.
- **Safe by default:** read-only, deny-by-default, per-agent identity, least privilege, explicit human approval for side effects.

## Build (Windows x64)
Requirements: Visual Studio 2022 with C++ desktop workload, CMake >= 3.20.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
.\build\Release\meta-sec.exe --help
.\build\Release\meta-sec.exe status
.\build\Release\meta-sec.exe status --json
```

MVP-0 reads computer name, Windows Firewall profile enabled states via `INetFwPolicy2`, and aggregate Windows Security Center AV health via `WscGetSecurityProviderHealth` where available. Windows Server may not support the latter. **It does NOT yet read true Defender real-time protection state, signature age, malware detections or Windows build.** An incomplete observation must not be reported as `PROTECTED`.

## Start here
- [Developer handoff — scope, architecture, goals, gates, test plan](docs/HANDOFF.md)
- [Roadmap MVP 0–9](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security baseline](docs/SECURITY.md)
- [CLI contract](docs/CLI.md)
- [Acceptance criteria](docs/ACCEPTANCE.md)

## License
MIT for original project code. Third-party components retain their respective licenses.
