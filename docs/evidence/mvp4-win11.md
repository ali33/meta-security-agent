# MVP-4 evidence: Windows 11 Pro (developer workstation, NON-ADMIN)

Captured 2026-10-31 from branch `feat/mvp4-service` (from `main` 4e937e7). Host name and Windows account are redacted.

**Headline: what runs without Administrator rights is proven; the service itself was never installed or run under the Service Control Manager here, and reboot survival was not tested.**

## Environment
| Item | Value |
|---|---|
| OS | Windows 11 Pro 10.0.26200, not elevated; Defender `Not running`, Bitdefender active |
| Compiler / build | MSVC 19.44.35229.0, CMake 4.0.2, x64 Release, `/W4 /WX /sdl /guard:cf`, link `/guard:cf /CETCOMPAT /DEPENDENTLOADFLAG:0x800` |
| SQLite | 3.54.1 amalgamation vendored (public domain), SHA3-256 of the zip verified against sqlite.org; see `third_party/sqlite/README.md` |
| `meta-sec.exe` SHA256 | `a60e8693a7c8ee93d628271852d89e0872eb746d01e48a95dedc4f4df0bab1d2` (build before the final docs-only commits) |
| ctest | 38/38 passed (store, observer, ipc, service model, install flow, cli parser, real named-pipe integration, e2e) |

## Real runs (non-admin)
- `service status` (nothing installed): `Service: MetaSecAgent - not installed`, `Result: OBSERVED`, exit 0; `sc query MetaSecAgent` => error 1060 (does not exist) before and after every run.
- `service install --dry-run` and `service install` with stdin not a console: `REFUSED_NOT_ELEVATED (exit 4)`; the binary-path rule also reports REFUSED (build dir is not under Program Files). Nothing asked, nothing changed.
- Foreground observer: `service run --console --max-polls 4 --interval 1 --confirm 1 --data-dir <temp> --pipe-name <random>` => exit 0, `events.db` created, closing line `[STOPPED] max_polls after 4 polls, 2 events, 0 store errors` (the 2 events are the service_started/service_stopped lifecycle rows; no setting changed).
- While it ran, `service status --pipe-name <random> --json` read over the real pipe: `ipc.reach=OK`, `health=OK`, `polls=2`, `events_total=1`, `store_errors=0`; `service events --limit 5` listed `[SERVICE STARTED]`.
- After the observer exited, `service events` => `UNREACHABLE: status pipe not found`, exit 3 (standalone commands still work).
- Restart in the same data dir: a second run added its own lifecycle rows and no duplicates (also asserted by the integration test).

## NOT tested
Install/uninstall for real; running under SCM (STOP/SHUTDOWN/PRESHUTDOWN); survival across reboot; LocalService access to Defender WMI and firewall (unmeasured: fallback is a different account, a human decision); Event Log record of install/uninstall; pipe/data-dir ACLs on a real installed service; Windows Server; a real Defender-primary machine.
