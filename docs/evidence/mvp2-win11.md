# MVP-2 evidence: Windows 11 Pro (lab: developer workstation)

Captured 2026-10-30 from branch `feat/mvp2-watch` (from `main` 8410f93, code commit `dcfa622`). Hostname replaced with `<REDACTED-HOST>`; nothing else edited.

## Environment
| Item | Value |
|---|---|
| OS | Microsoft Windows 11 Pro, 10.0.26200 (client) |
| Compiler | MSVC 19.44 (VS 2022 Build Tools), `/W4 /WX /EHsc /utf-8 /permissive- /sdl /guard:cf`; link `/guard:cf /CETCOMPAT /DEPENDENTLOADFLAG:0x800` |
| Build system | CMake 4.0.2, MSBuild 17.14, "Visual Studio 17 2022" x64, Release |
| Tests | ctest 19/19 passed: `core_unit`, `audit_unit`, `watch_unit` (5,865 checks), `json_roundtrip`, `audit_json_roundtrip`, `watch_ndjson_roundtrip`, and 13 end-to-end CLI cases including `cli_watch_text`, `cli_watch_json`, `cli_watch_bad_args` |
| Elevation | **Non-admin**. Elevated run: NOT tested |
| `meta-sec.exe` SHA256 | `cd81c55e020cb7d11ee313cb68d250db389e0a06b545280e589c6752b6bba177` (final build after review fixes; the runs below on the earlier build `2cb16b04...` except the Ctrl+Break run, repeated on the final build: exit 0, 8 ms) |

## Gate: "One controlled change generates one timestamped alert, no replay storm"
### Controlled change: proven with injected snapshots only
This machine is non-admin and the tool is read-only by rule, so **no real firewall/Defender/AV setting was changed and no real change was observed**. The detection loop (`run_watch`) takes its snapshot source, output, wait and stop signal as injected hooks, so a scripted sequence of snapshots drives the exact production code (`tests/test_watch.cpp`; the release binary has no test back door). Scripted sequence for `firewall.public` (interval 1, `--confirm 2`): ENABLED, ENABLED->DISABLED x2, UNKNOWN x2, ENABLED x2. Output, compacted (`binary: metasec_watch_tests --emit-ndjson`, polls timestamped 00:00:00..06):
```text
baseline (hostile test host name, 2 checks)
{"event":"change","observed_at_utc":"2026-10-30T00:00:02Z","first_observed_at_utc":"2026-10-30T00:00:01Z","check_id":"firewall.public","from":"ENABLED","to":"DISABLED","to_posture":"ATTENTION","confirmations":2,"error_code":""}
{"event":"observation_lost","observed_at_utc":"2026-10-30T00:00:04Z","first_observed_at_utc":"2026-10-30T00:00:03Z","check_id":"firewall.public","from":"DISABLED","to":"UNKNOWN","to_posture":"UNKNOWN","confirmations":2,"error_code":"HRESULT:0x80041003"}
{"event":"observation_restored","observed_at_utc":"2026-10-30T00:00:06Z","first_observed_at_utc":"2026-10-30T00:00:05Z","check_id":"firewall.public","from":"UNKNOWN","to":"ENABLED","to_posture":"OK","confirmations":2,"error_code":""}
{"schema_version":1,"command":"watch","event":"stopped","observed_at_utc":"2026-10-30T01:00:00Z","reason":"max_polls","polls":7,"events":3}
```
One transition = one event; the repeated DISABLED/UNKNOWN/ENABLED polls after each confirmation produce nothing. Unit tests also cover: no change over 20 polls, flapping (E,D,E,D... and with confirm 3), a one-poll UNKNOWN, candidate restart, added/removed checks, duplicate ids, `--confirm 1`, a seeded random sweep (3 x 2000 polls) asserting every event is a real transition, loop stop reasons, output failure, and determinism.

**NOT verified:** that Windows reports the corresponding state on a real machine when a setting is actually weakened, and the real latency from change to alert. Needs a lab machine with permission to toggle a firewall profile (and elevation), run `meta-sec watch`, toggle, and check for exactly one event.

### Real run (steady state, non-admin): no spurious events
`meta-sec watch --interval 2 --max-polls 3` (exit 0, stderr 0 bytes):
```text
META Security Agent v0.1.0 | Standalone | Read-only | Watch
2026-10-30T05:51:33Z [BASELINE] host <REDACTED-HOST> | windows 10.0.26200 (client) | every 2s, confirm 2 polls
  firewall.domain: ENABLED (OK)
  firewall.private: ENABLED (OK)
  firewall.public: ENABLED (OK)
  antivirus.windows_security_center: GOOD (OK)
  antivirus.defender.antivirus: PASSIVE (NOT_APPLICABLE)
  antivirus.defender.realtime_protection: PASSIVE (NOT_APPLICABLE)
2026-10-30T05:51:38Z [STOPPED] max_polls after 3 polls, 0 change events
```
`meta-sec watch --json --interval 2 --max-polls 3`: exit 0, stderr 0 bytes, 2 lines (`baseline` with 6 checks, then `{"schema_version":1,"command":"watch","event":"stopped","observed_at_utc":"2026-10-30T05:51:43Z","reason":"max_polls","polls":3,"events":0}`).

### Stop and bad arguments
- Ctrl+Break sent to a `watch --json --interval 2` process (Python `CREATE_NEW_PROCESS_GROUP` + `CTRL_BREAK_EVENT`): exit **0**, process gone 13 ms (earlier build) / 8 ms (final build) after the signal, stderr empty, last line `"event":"stopped","reason":"interrupted","polls":3`. Ctrl+C uses the same handler (`CTRL_C_EVENT` could not be delivered by the harness because the test shell ignores it; not separately observed).
- `watch --interval 0` -> exit 2, stderr `meta-sec: --interval must be an integer from 1 to 3600, got: 0` plus usage, stdout empty. `--confirm 11` likewise.

### Resource use (one run, `--interval 1 --max-polls 130`, ~130 s, sampled every 20 s)
```text
t=20s  handles=176 private=5423104 threads=4 cpu=0.77
t=40s  handles=175 private=5492736 threads=4 cpu=1.34
t=60s  handles=175 private=5693440 threads=4 cpu=2.11
t=80s  handles=178 private=5767168 threads=4 cpu=2.92
t=100s handles=180 private=6250496 threads=4 cpu=3.44
t=120s handles=178 private=5902336 threads=4 cpu=3.95
exit=0, stderr=0 bytes
```
Handles stay in 175..180 and private bytes in 5.4..6.3 MB with no monotonic growth over ~120 polls (fluctuation, not a leak, in this window). CPU is about 0.03 s per poll (about 3% at a 1 s interval), so about 0.1% at the 30 s default; between polls the process blocks in `WaitForSingleObject`. This is **not** a long soak test (hours); COM interfaces are created and released inside each provider call inside one apartment held for the whole run.

## What was NOT tested
- A real weakened configuration and a real change-to-alert latency (above).
- Windows Server / absence of Security Center (the e2e cases accept exit 0 or 3, so they should pass on `windows-latest`; not run there yet).
- Elevated execution; a second machine; runs of hours or days; console close (`CTRL_CLOSE_EVENT`: the handler waits up to 3 s for the closing line; implemented, not exercised). A snapshot exception mid-run is covered only by a unit test with a throwing fake.
