# Developer handoff — META Security Agent

Version: 1.0 · 2026-10-30 · Open-source public repository `ali33/meta-security-agent`

## A. Product mission and non-goals

Build a credible **local Windows security posture and antivirus/firewall observability tool** in C++20, usable with no account, Internet, service or Center. Later permit optional enrollment into a security Center **without changing the local security engine**. Prioritize demonstrably working features over architectural scaffolding.

The earliest visible value is the command `meta-sec status`: actual firewall profiles, actual Windows antivirus-provider observation, explicit unavailable statuses, repeatable JSON. The next visible value is `meta-sec audit` finding verifiably weak settings.

**Not in MVP 0:** proprietary AV engine, real-time EDR, malware quarantine, kernel driver, ransomware prevention, fleet web UI, arbitrary remote shell, automatic remediation, cloud deployment. Do not claim GravityZone feature parity.

## B. Binding decisions

1. C++20, Windows x64 first, CMake/MSVC; minimal dependencies.
2. Standalone is the default, not a fallback. Center is optional, never a prerequisite for local checks.
3. Console UI for Agent first. Center is developed as CLI before any web UI.
4. Read-only and deny-by-default. No general-purpose remote command execution.
5. Distinct OS security provider abstraction: Defender/Windows Security Center and Windows Firewall providers; explicitly report unsupported APIs.
6. CLI + future Windows Service use one C++ security-core library; Center connector is separable.
7. All returns machine-readable JSON with versioned schema and reliable exit codes.
8. Security baseline: agent identity -> least privilege -> sandbox -> audit -> policy gate -> human approval -> rollback.
9. Public source only: no company-specific secrets, internal IPs, private network maps or credentials.
10. A milestone is completed only after executable demo, real OS evidence, automated tests, negative tests, docs, and recovery plan.

## C. Current repository state

This repository contains the **MVP-0 source skeleton**, not a tested Windows executable. Initial `src/main.cpp` implements `meta-sec status [--json]`, Windows host name, `INetFwPolicy2` firewall profiles and Security Center aggregate antivirus health. The latter is not a reliable Defender-specific verdict on Windows Server. The platform value currently intentionally omits Windows build. No local antivirus action or network call occurs.

**Verification task for receiving team:** compile using MSVC and run on Windows 10/11, then Windows Server lab; capture redacted output, API return codes and the test environment. Fix compilation/formatting issues before calling MVP-0 accepted. Review JSON escaping, COM init and release, supported provider behavior and thread ownership.

## D. Target runtime architecture

```text
                  STANDALONE (default)
 +--------------------------------------------------+
 | meta-sec CLI                                    |
 |        |                                         |
 | Security Core (C++20)                            |
 |   |-- Host/OS provider                            |
 |   |-- Windows AV/Defender provider                |
 |   |-- Windows Firewall provider                  |
 |   |-- Findings / Audit Engine (MVP-1)             |
 |   |-- Event watching (MVP-2)                     |
 |   |-- Local policy + event store (MVP-4/5)       |
 +-------------------+------------------------------+
                     |
               optional join, MVP-7
                     |  mTLS + per-device identity
                     v
 +--------------------------------------------------+
 | Center API + PostgreSQL + Center CLI (MVP-8)      |
 | Web console (later; not a prerequisite)          |
 +--------------------------------------------------+
```

For MVP 0–3 CLI directly invokes core. At MVP-4 optional Windows Service owns privileged long-running collectors; local authenticated IPC handles commands, avoids running CLI elevated merely to display status. Center observes signed/validated agent data; it cannot bypass agent's local policy gate.

## E. Concrete implementation workstreams

**CLI:** build stable command routing for `--help`, `status`, `status --json`; consistent stderr diagnostics; tests for invalid args; UTF-8 console and machine-readable JSON. Keep JSON clean on stdout, send errors to stderr.

**Providers:** implement typed results `check_id, observed_at_utc, state, evidence, source, error_code`. Distinguish API unavailable from unhealthy. Never set `PASS` on failed calls. If Defender-specific state cannot be determined, report `UNKNOWN` or `NOT_SUPPORTED`.

**Audit:** establish versioned rule IDs; `PASS/FAIL/UNKNOWN/NOT_APPLICABLE`; severity and remediation guidance, evidence and data-source provenance; deterministic unit tests for each rule.

**Windows security:** prefer native COM/Windows APIs where adequate. Use supported Defender management interfaces for Defender-specific state, signature age and detection events in later MVP. Avoid untrusted PowerShell parsing as the sole security proof. Never silently disable OS defenses.

**Persistence (later):** local SQLite for event cursor/checkpoint, proper migrations and disk quotas. Avoid storing file content or secrets unnecessarily.

**Center (later):** enrollment with device approval and per-device credentials, outbound-only connectivity, certificate pinning or trusted PKI with rotation, mTLS, typed protobuf commands, RBAC and audit.

## F. Roadmap, live demos, and done criteria

| Stage | Estimate | Visible goal | Demo command / proof | Exit gate |
|---|---:|---|---|---|
| MVP 0 | 1–2 days | Single executable reads security status | `meta-sec status --json` | Real Windows values, explicit unknown, successful MSVC build |
| MVP 1 | 2–3 days | Find weak security settings | `meta-sec audit` | Controlled secure/insecure lab profiles produce correct findings |
| MVP 2 | 3–5 days | Detect status changes | `meta-sec watch` | One controlled change generates one timestamped alert, no replay storm |
| MVP 3 | 3–5 days | Trigger Defender scan on demand | `meta-sec scan --quick` | Explicit local approval, real status and errors, not a fake scan |
| MVP 4 | 4–6 days | Run background observer | `meta-sec service status` | Service survives reboot, local CLI works offline, events persist |
| MVP 5 | 4–6 days | Check local baseline policy | `meta-sec policy check` | Evidence-backed drift report for known rule violation |
| MVP 6 | 5–8 days | Safe remediation | `meta-sec fix --dry-run` | Reject/no-op without approval; scoped action and rollback in lab |
| MVP 7 | 5–8 days | Optional join Center | `meta-sec center join/status/leave` | Center disconnect does not break local checks |
| MVP 8 | 7–10 days | Central fleet console | `meta-center devices list` | >=3 lab agents, RBAC, authenticated audit, no web dependency |
| MVP 9 | separately estimated | Linux CLI and later web UI | `meta-sec status` on Ubuntu, later web demonstration | Defined parity and distinct Windows/Linux acceptance suites |

Estimates are engineering planning ranges, not commitments. Stop and reassess when native integration or security testing proves harder.

### Immediate MVP 0 acceptance script
1. `cmake -S . -B build -A x64` succeeds.
2. `cmake --build build --config Release` succeeds with reproducible toolchain.
3. `meta-sec --help` prints supported commands and exits 0.
4. `meta-sec status` produces real host/firewall/AV health signals on lab Windows.
5. `meta-sec status --json` is valid JSON and contains no unexpected stdout noise.
6. Compare firewall result against Windows UI/PowerShell on two machines.
7. Test API unavailable case, Windows Server behavior, invalid args and non-admin execution.
8. No change to OS firewall/Defender settings, no secrets, no network dependency.
9. Output never claims all-protected solely from WSC.
10. Save redacted test outputs, Windows build, compiler version, SHA of tested binary.

### MVP 1 acceptance
At least six independently testable checks: 3 firewall profile states, AV provider health unknown handling, antivirus disabled/poor state when observable, and signature freshness only where a reliable provider exists. Every failure has evidence, severity and remediation text; unknown is not converted into pass.

## G. CLI and data contract

Proposed:
```text
meta-sec --help
meta-sec status [--json]
meta-sec audit [--json]          # MVP-1
meta-sec watch                   # MVP-2
meta-sec scan --quick            # MVP-3; human approval required
meta-sec service status          # MVP-4
meta-sec policy check            # MVP-5
meta-sec fix --dry-run           # MVP-6
meta-sec center join/status/leave # MVP-7
meta-center devices list         # MVP-8
```

Exit codes: 0 successful read with no known violation; 1 confirmed policy violation (audit); 2 command/engine error; 3 incomplete or insufficient observation. A status inspection is **not** a full AV security certification; overall names must reflect the distinction.

Suggested JSON `schema_version: 1` fields: `product, version, mode, hostname, observed_at_utc, checks[], overall`. Each check has `name, state, source, error` initially; evolve additively with `evidence`, timestamps and rule IDs.

Implemented additive changes to schema_version 1 (MVP-0): per-check `check_id`, `observed_at_utc`, `posture` (`OK|ATTENTION|UNKNOWN|NOT_APPLICABLE`), `error_code`, `evidence{}`; top-level `version`, `platform{}`, `attention[]`; new state `PASSIVE`; `overall` may be `OBSERVED_WITH_ISSUES`. `status` exits 0 for both OBSERVED values (it observes; only `audit` returns 1), so a disabled firewall/Defender or poor WSC shows in `attention[]`/`posture`, not in the exit code. See docs/CLI.md.

## H. Security baseline: hard release blockers

- All data gathering read-only unless a separately approved action demands otherwise.
- Every agent has dedicated device identity/credentials; service identity is separate from humans.
- Least privilege; split privileged OS service from user CLI and Center connector.
- Never include tokens, private keys, credentials or sensitive telemetry in prompts, stdout or logs.
- Strict schema validation, command allowlist, signed policy and approved package updates.
- Firewall/write/delete/scan/deploy/admin actions need explicit human approval and recorded actor; where possible dry-run first.
- Blast radius bounds, canary first, kill switch and automatic timeout rollback for risky changes.
- Center unavailability: retain last trusted local protection and refuse fresh unverified actions.
- Fail closed on missing rights, unclear policy, failed validation or missing approval.
- CI compiles and tests only; no publishing or deployment without approval.

## I. Execution and review process for another team

- Create one issue per MVP with a live demo script, exact expected observable signals, acceptance checklist, security gate, and rollback notes.
- Open short-lived feature branches `feat/mvp0-...` and PRs into protected `main`.
- Minimum PR: code, tests, example output, update to documentation, security implications, supported Windows build and explicit non-goals.
- Human reviewer signs off each side-effect capability; do not merge unsafe remote execution or "autofix" without approval.
- Release version tags `v0.1.0-mvp0`, `v0.2.0-mvp1`, etc. **Only after tests actually pass.**
- Status report for every MVP: goal, what can be run, demo evidence, PASS/FAIL of each gate, uncovered OS variants, next MVP.
- License: MIT for original code, verify each third-party dependency's license.

## J. Known risks / explicit decisions

1. Windows Security Center aggregates AV provider health, not guaranteed Microsoft Defender-specific state.
2. Windows Server support differs: provider interface must emit `NOT_SUPPORTED` when appropriate.
3. Firewall profile enabled state alone is not sufficient to prove safe effective rules.
4. MVP-3 "scan" uses OS-installed engine; no custom antivirus engine.
5. On-access protection, behavioral EDR, containment, quarantine and signature feeds are **not** delivered by this prototype.
6. No production agent rollout before signature, packaging, update/rollback, telemetry privacy and Windows compatibility validation.

## K. Definition of handoff complete

Receiving team can clone repo, explain target architecture and decisions, build on Windows, run explicit CLI commands, locate the next missing work items, identify safety constraints, and show demonstrable proof for each MVP without needing original author contact.

**First coding assignment:** make MVP-0 Windows build green, introduce Defender-specific data source with clear fallback, add automated JSON/argument tests, provide redacted output from Windows 11 and Windows Server lab. Do not build a Center or UI yet.
