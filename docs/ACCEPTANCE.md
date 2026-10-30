# Acceptance and demonstration contract

## MVP-0 must pass
- [ ] Compile on Windows with documented MSVC and CMake versions.
- [ ] `meta-sec --help` works.
- [ ] `meta-sec status` reports actual hostname and firewall profiles.
- [ ] `meta-sec status --json` parses successfully as JSON.
- [ ] WSC health does not masquerade as Defender-specific realtime protection.
- [ ] Unknown / Windows Server unsupported cases explicitly reported.
- [ ] Non-admin invocation tested; invalid arguments rejected.
- [ ] No network or database required.
- [ ] No changes to firewall, antivirus, filesystem security settings.
- [ ] At least one automated negative test and example redacted output.
- [ ] Windows environment and tested binary SHA captured.

## Every further MVP
- [ ] Real executable demonstration.
- [ ] Evidence on actual supported Windows/Ubuntu system.
- [ ] User-visible goal and precise demonstration command.
- [ ] Expected result and error states.
- [ ] Unit / integration tests and negative security tests.
- [ ] Approval gate for side-effects.
- [ ] Rollback/recovery procedure.
- [ ] Human acceptance recorded.

**No checkbox is pre-checked.** Source upload is not proof that test gates have passed.

## MVP-0 status record (2026-10-30, branch `feat/mvp0-build-defender-tests`)
Boxes above stay unchecked until a human accepts. Evidence so far, details in [evidence/mvp0-win11.md](evidence/mvp0-win11.md):

| Item | Result |
|---|---|
| MSVC/CMake build | PASS on Windows 11 Pro 10.0.26200 (MSVC 19.44, CMake 4.0.2, `/W4 /WX`) |
| `--help` | PASS (exit 0) |
| Real hostname and firewall profiles | PASS, matches `Get-NetFirewallProfile` on one machine |
| `status --json` valid JSON, clean stdout | PASS (checked by CMake's JSON parser in CTest) |
| WSC not presented as Defender state | PASS, separate checks; on the lab machine WSC=GOOD while Defender is PASSIVE (not running, another AV healthy) |
| Unknown / unsupported / attention reported explicitly | PASS in unit tests (156 checks, fakes for every provider decision); not observed on a real OS |
| Non-admin run, invalid arguments | PASS (non-admin session; bad args exit 2 on stderr) |
| Elevated run, Windows Server, second machine | NOT TESTED |
| No network/db, no setting changes | by design (read-only COM/WMI queries); no network code |
| Automated negative test + redacted output + SHA | PASS |


## MVP-1 status record (2026-10-30, branch `feat/mvp1-audit`, stacked on `feat/mvp0-build-defender-tests`)
Boxes stay unchecked until a human accepts. Details and raw output in [evidence/mvp1-win11.md](evidence/mvp1-win11.md).

| Item (HANDOFF section F, MVP 1) | Result |
|---|---|
| Visible goal: `meta-sec audit` finds weak settings, with rule id/version, PASS/FAIL/UNKNOWN/NOT_APPLICABLE, severity, remediation, evidence, provenance | PASS on one Windows 11 client (7 rules) |
| At least six independently testable checks | PASS: 3 firewall profiles, WSC health (unknown handling), active AV engine (includes Defender PASSIVE + another AV on), Defender real-time, signature age. Each is a pure function in `src/core/audit.cpp` |
| Signature freshness only from a reliable provider | PASS by design: Defender only, only when `AMRunningMode` is `Normal`; otherwise NOT_APPLICABLE/UNKNOWN. Threshold is the constant `kSignatureMaxAgeDays = 3` |
| Every failure has evidence, severity and remediation | PASS (unit test `check_shape` on every FAIL; e2e checks the fields on every rule) |
| UNKNOWN is never converted to PASS | PASS (negative tests, plus an invariant sweep over 4 x 4 x 6 x 9 x 6 combinations) |
| Exit codes 0 / 1 / 2 / 3 | PASS (unit and e2e). Decision: FAIL (1) outranks UNKNOWN (3) |
| Automated tests incl. negative | PASS: ctest 14/14; core 180 checks, audit 79,909 checks (see evidence) |
| Controlled secure/insecure lab profiles give correct findings | **PARTIAL.** Verified with fixture profiles loaded into the core (no OS setting was changed; the machine is non-admin and read-only by rule). **Not verified on a real lab machine with weakened firewall/Defender/AV** |
| Real-OS run | PASS on Windows 11 Pro 10.0.26200, non-admin: all rules PASS/NOT_APPLICABLE, exit 0 (this machine is healthy, so no real FAIL was observed) |
| Windows Server (`ROOT\SecurityCenter2` absent -> NOT_SUPPORTED path), elevated run, second machine | NOT TESTED |
| Read-only, no network, no secrets | by design; WMI/COM queries only |


## MVP-2 status record (2026-10-30, branch `feat/mvp2-watch`, from `main` at `8410f93`)
Boxes stay unchecked until a human accepts. Details and raw output in [evidence/mvp2-win11.md](evidence/mvp2-win11.md).

| Item (HANDOFF section F, MVP 2: "One controlled change generates one timestamped alert, no replay storm") | Result |
|---|---|
| `meta-sec watch` runs, polls the status collectors read-only, stops on Ctrl+C / Ctrl+Break or `--max-polls` | PASS on Windows 11 (non-admin). Ctrl+Break verified: stops within 13 ms, `stopped` line, exit 0, empty stderr |
| One change -> exactly one timestamped event (`observed_at_utc`, `check_id`, `from`, `to`, evidence) | PASS with **injected fake snapshots** (`tests/test_watch.cpp`, pure `WatchTracker` + loop with hooks) |
| Controlled change on a real lab machine | **NOT VERIFIED.** The machine is non-admin and read-only by rule; no firewall/Defender/AV setting was changed. The real run saw 0 changes in a healthy steady state |
| No replay storm | PASS: baseline printed once; an unchanged state yields no line (unit tests, 20-poll steady loop, real 3-poll and 130-poll runs) |
| Flapping / transient errors | PASS: debounce `--confirm` (default 2 consecutive polls); E,D,E,D... and one-poll UNKNOWN produce no event |
| UNKNOWN never reported as "disabled" | PASS: persistent loss is `observation_lost` (to=UNKNOWN), recovery is `observation_restored`; asserted that neither rendering contains DISABLED |
| NDJSON valid, clean stdout, stderr empty | PASS: every line parsed by CMake's JSON parser (unit stream and real `watch --json`) |
| Bad arguments -> exit 2, stderr only | PASS (16 unit cases + e2e `watch_bad_args`) |
| Resource use over time | PASS on one 130-poll run, see evidence (handles/private bytes flat; CPU low). Not a soak test |
| Windows Server (WSC absent), elevated run, second machine | NOT TESTED (CI on windows-latest runs the e2e cases, which accept exit 0 or 3) |
| Read-only, no network, no persistence | by design; no new Windows API besides `SetConsoleCtrlHandler` and an event for the stop signal |
