# Architecture — one core, two operating modes

## Standalone (default)
`meta-sec CLI -> Local C++ Security Core -> Windows Host / Defender or Windows Security Center / Firewall APIs`.

The standalone CLI must never require server, database, Internet or enrollment. Future Windows Service and CLI consume the same core and authenticated local IPC. Use least privilege and read-only OS APIs initially.

## Managed (optional after MVP-7)
`Local Core -> optional Center Connector (per-agent mTLS) -> C++ Center API/PostgreSQL -> Center CLI`. Web console comes **after** Center CLI. Losing Center leaves local checks working; remote commands must pass agent-local policy gates.

## Data contracts
Each observation carries result/status, source, observed time, evidence, error code. Missing API response => UNKNOWN/NOT_SUPPORTED. OS telemetry does not prove full antivirus protection. JSON schema versioning and deterministic exit codes are mandatory.

## Component boundaries
- `src/main.cpp` current MVP-0 CLI, to be modularized.
- `src/core/` models, normalized results, audit logic.
- `src/providers/windows/` AV/Defender and Firewall integrations.
- `src/service/` future Windows Service with local authenticated IPC.
- `src/center-connector/` optional transport, identity and sync.
- `center/` future C++ API and `meta-center` CLI.
- `tests/` unit, command-line, Windows integration and denial tests.

Do not introduce dependencies on Center in local-provider interfaces.
