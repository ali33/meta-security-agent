# MVP Roadmap and live goals

Strategy: standalone first, C++ CLI first, Windows first; Center as an optional later enhancement. See [HANDOFF.md](HANDOFF.md) for acceptance, risks and developer tasks.

| MVP | Estimate | Goal | Observable demo | Acceptance |
|---|---|---|---|---|
| 0 | 1–2 days | Single Windows binary | `meta-sec status --json` | Real OS results and unknown handling; MSVC build |
| 1 | 2–3 days | Security posture audit | `meta-sec audit` | PASS/FAIL/UNKNOWN, evidence, lab validation |
| 2 | 3–5 days | Continuous observation | `meta-sec watch` | Controlled change triggers event, no duplicates |
| 3 | 3–5 days | AV quick scan | `meta-sec scan --quick` | Approved real OS scan, visible status |
| 4 | 4–6 days | Windows Service | `meta-sec service status` | Offline operation, reboot continuity, local IPC |
| 5 | 4–6 days | Local policies | `meta-sec policy check` | Detect real configuration drift |
| 6 | 5–8 days | Scoped remediation | `meta-sec fix --dry-run` | Human approval, dry-run, rollback tested |
| 7 | 5–8 days | Optional Center enrollment | `meta-sec center status` | Disconnect Center; local checks still work |
| 8 | 7–10 days | Multi-agent Center **CLI** | `meta-center devices list` | >=3 enrolled lab endpoints, RBAC and log |
| 9 | follow-on | Linux Agent, later web | Linux CLI live demo | Cross-platform tests and separate web acceptance |

**Progress:** MVP 0 (`status`, PR #2), MVP 1 (`audit`, PR #3) and MVP 2 (`watch`, branch `feat/mvp2-watch`) are implemented and tested on one Windows 11 client; none is human-accepted. MVP 1 lab validation of weak configurations used fixtures, not a weakened real machine ([evidence](evidence/mvp1-win11.md)). MVP 2 change detection is proven with injected fake snapshots, not by changing a real setting ([evidence](evidence/mvp2-win11.md)). Windows Server is untested.

Every MVP must provide: working build, real on-device observation, repeatable demonstration, at least one negative test, security review, release notes and recovery instructions. UI and infrastructure are deferred intentionally.

**First delivery milestone:** MVP 0–1 on one Windows endpoint. **Second:** MVP 2–4 persistent standalone monitoring. **Third:** MVP 5–6 safe policy/remediation. **Fourth:** MVP 7–8 optional centralized management. Linux and web are explicitly after core CLI.

Non-goals early on: AV engine, EDR replacement, kernel drivers, ransomware blocker, blanket remote execution or production auto-remediation.
