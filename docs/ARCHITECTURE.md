# Architecture — one core, two operating modes

## Standalone (default)
`meta-sec CLI -> Local C++ Security Core -> Windows Host / Defender or Windows Security Center / Firewall APIs`.

The standalone CLI must never require server, database, Internet or enrollment. Future Windows Service and CLI consume the same core and authenticated local IPC. Use least privilege and read-only OS APIs initially.

## Managed (optional after MVP-7)
`Local Core -> optional Center Connector (per-agent mTLS) -> C++ Center API/PostgreSQL -> Center CLI`. Web console comes **after** Center CLI. Losing Center leaves local checks working; remote commands must pass agent-local policy gates.

## Data contracts
Each observation carries result/status, source, observed time, evidence, error code. Missing API response => UNKNOWN/NOT_SUPPORTED. OS telemetry does not prove full antivirus protection. JSON schema versioning and deterministic exit codes are mandatory.

## Component boundaries
- `src/main.cpp` CLI entry: parses arguments (`core/cli`), calls the core and the Windows layer, renders output.
- `src/core/` OS-independent logic: models, audit, watch, scan gate, service status/install flows, observer, event store (SQLite), IPC line protocol, JSON.
- `src/win/` Windows layer: Defender/Firewall/Security Center providers, and the optional service (`service_win` host, `ipc_win` named pipe, `scm_win` Service Control Manager, `datadir_win` protected data directory). The service is the same `meta-sec.exe` started with `service run --scm`.
- Local IPC is a read-only named pipe (STATUS/HEALTH/EVENTS) restricted to interactive local users; it is not authenticated beyond that (see SECURITY.md).
- `src/center-connector/` optional transport, identity and sync.
- `center/` future C++ API and `meta-center` CLI.
- `tests/` unit, command-line, Windows integration and denial tests.

Do not introduce dependencies on Center in local-provider interfaces.
