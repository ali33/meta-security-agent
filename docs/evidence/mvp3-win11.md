# MVP-3 evidence: Windows 11 Pro (lab: developer workstation)

Captured 2026-10-30 from branch `feat/mvp3-scan` (from `main` 04a7978). Nothing was edited except that this machine's host name and Windows account never appear in the outputs below (the refused runs never reach the step that reads the account).

**Headline: on this machine a real scan could not be started, and that is the correct, proven result.** The machine's Defender is `Not running` (Bitdefender is the active antivirus) and the process is not elevated. What is proven here is the **refusal** behaviour. A real quick scan on a machine where Defender is the primary engine was **never run**.

## Environment
| Item | Value |
|---|---|
| OS | Microsoft Windows 11 Pro, 10.0.26200 (client) |
| Compiler | MSVC 19.44 (VS 2022 Build Tools), `/W4 /WX /EHsc /utf-8 /permissive- /sdl /guard:cf`; link `/guard:cf /CETCOMPAT /DEPENDENTLOADFLAG:0x800` |
| Build system | CMake 4.0.2, MSBuild 17.14, "Visual Studio 17 2022" x64, Release |
| Tests | ctest 24/24 passed: `core_unit` (180 checks), `audit_unit` (79,909), `watch_unit` (5,865), **`scan_unit` (376 checks)**, 3 JSON round-trips, and 16 e2e CLI cases including `cli_scan_dry_run`, `cli_scan_json`, `cli_scan_no_approval`, `cli_scan_bad_args` |
| Elevation | **Non-admin**. Elevated run: NOT tested |
| Defender state (this machine) | `AMRunningMode` = `Not running`; Security Center lists one active third-party antivirus (Bitdefender) |
| `meta-sec.exe` SHA256 | `1289cc42e03de050f274a30d904b2ad8321ffd9c005ca102dff381f5a7cf0256` (build of commit "fix(scan)" below) |
| Dependencies | `dumpbin /dependents`: ole32, OLEAUT32, **Secur32 (new, present on all Windows incl. Server)**, KERNEL32, ADVAPI32, MSVC runtime, UCRT |

## Gate: real run, text (`--dry-run`, exit 4)
```text
META Security Agent v0.1.0 | Standalone | Scan (quick) | DRY RUN
Observed: 2026-10-30T10:47:00Z
Gate: REFUSED (MODE_NOT_RUNNING) | Defender mode: Not running
Result: REFUSED_NOT_APPLICABLE (exit 4)
  No scan was started: Defender is not running, so it cannot scan. Security Center reports these antivirus products active: Bitdefender Endpoint Security Tools Chống Malware. Open that product and run its own scan; META Security Agent cannot command it.
```

## Real run, JSON (`scan --quick --dry-run --json`, exit 4, stderr empty)
```json
{"schema_version":1,"command":"scan","scan_type":"quick","product":"META Security Agent","version":"0.1.0","mode":"standalone","dry_run":true,"observed_at_utc":"2026-10-30T10:46:51Z","finished_at_utc":"2026-10-30T10:46:51Z","status":"REFUSED_NOT_APPLICABLE","exit_code":4,"message":"No scan was started: Defender is not running, ...","gate":{"allowed":false,"code":"MODE_NOT_RUNNING","defender_running_mode":"Not running","message":"...","active_antivirus_products":["Bitdefender Endpoint Security Tools Chống Malware"]},"elevated":false,"approval":{"required":true,"method":"typed_confirmation_on_console","asked":false,"granted":false,"reason":"","actor":"","approved_at_utc":""},"start":{"attempted":false,"api":"WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpScan.Start(ScanType=1)","exec_result":"","completion_result":"","return_value":"","wait":""},"verification":{"before":{"quick_scan_start_utc":"","quick_scan_end_utc":""},"after":{"quick_scan_start_utc":"","quick_scan_end_utc":""},"new_scan_confirmed":false}}
```
`start.attempted=false`, `approval.asked=false`: the gate refused before any approval step.

## Approval gate against the real binary
- `printf 'START QUICK SCAN\r\n' | meta-sec scan --quick` (exact phrase on a **piped** stdin): exit **4**, `REFUSED_NOT_APPLICABLE` here (the gate refuses first on this machine).
- Because on this machine the gate always refuses first, the approval step cannot be reached through the real binary here. It is proven with the fakes in `tests/test_scan.cpp` (not with the real OS): a sweep of 5 modes x 5 typed lines x console/no-console asserts that `start_quick_scan` is called **iff** mode is `Normal` AND stdin is a console AND the line is the exact phrase plus a terminator; plus per-case tests for EOF, read error, interrupted read, no visible prompt, wrong text, missing or doubled terminator, and a gate that flips to passive between approval and `Start`. A mutation check (deleting the `NOT_A_CONSOLE` test from `evaluate_approval`) made 9 checks fail, so the sweep does detect a removed approval check.
- On a CI runner with Defender in `Normal` mode, `cli_scan_no_approval` reaches the approval step and must get `NOT_A_CONSOLE` (asserted in the test); that path is **not** exercised on this machine.
- Typing the phrase at a real console and answering the prompt: **not exercised by any automation**. Needs a human at a console on a Defender-primary machine.

## Bad arguments (exit 2, stdout empty, diagnostic on stderr)
```text
meta-sec scan --quick --yes   -> meta-sec: unexpected argument: --yes      (exit 2)
meta-sec scan --full          -> meta-sec: unexpected argument: --full     (exit 2)
```
Also covered by `cli_scan_bad_args`: `scan`, `scan --json`, `scan --dry-run`, `scan --custom C:\`, `scan --quick --full`, `--force`, a repeated `--quick`, an extra word.

## Review
An independent code review (separate agent) answered "no path starts a scan without human confirmation on a real console" from the code, and raised: a MEDIUM (type-ahead not flushed before the prompt), and LOWs (terminator not required, exception after `Start` could lose the report, no-call-result mapped to a failure, an old scan could be mistaken for ours, console-mode calls unchecked). All were fixed in the commit after the review and have unit tests where testable (flush and console-mode checks are Windows-API calls with no automated coverage).

## What was NOT tested
- A real quick scan on any machine; Defender with `AMRunningMode` = `Normal`; an elevated run.
- The real `ACCESS_DENIED` path (the gate refuses before `Start` on this machine).
- Whether `MSFT_MpScan.Start` blocks for the scan duration, what `ReturnValue` it yields, and the exact `ScanType` CIM type on a given build (the code reads the type from the class definition and fails closed on an unexpected one).
- That `QuickScanStartTime` / `QuickScanEndTime` update the way the code assumes on every Windows build.
- Cancelling: no cancel call is used; Ctrl+C only stops waiting.
- Windows Server (the CI runner is Windows Server; the new tests never reach a real scan there, and the e2e cases accept exit 4 or, for `--dry-run`, 0).
- A real console prompt, including ConPTY, Ctrl+C at the prompt, and pasted text.
