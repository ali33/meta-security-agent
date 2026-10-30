# MVP-0 evidence: Windows 11 Pro (lab: developer workstation)

Captured 2026-10-30. Hostname replaced with `<REDACTED-HOST>`; nothing else edited.

## Environment
| Item | Value |
|---|---|
| OS | Microsoft Windows 11 Pro, 10.0.26200 (client) |
| Compiler | MSVC 19.44.35229.0 (VS 2022 Build Tools, toolset 14.44.35207), `/W4 /WX /EHsc /utf-8 /permissive-` |
| Build system | CMake 4.0.2, MSBuild 17.14, generator "Visual Studio 17 2022" x64, Windows SDK 10.0.26100.0 |
| Commands | `cmake -S . -B build -A x64` then `cmake --build build --config Release` |
| Tests | `ctest -C Release`: 9/9 passed (unit binary with 156 checks, JSON round-trip through CMake parser, 7 end-to-end CLI cases) |
| Elevation | **Non-admin** (`IsInRole(Administrator)` = False). Elevated run: NOT tested |
| `meta-sec.exe` SHA256 | `1ef5f7eff3ea10522b12b07d2999e74825148be48a5fa2f31dc950f7dcc48679` |

SHA256 identifies the binary that produced the output below; a rebuild with a different toolchain or commit may differ.

## Independent cross-check (read-only PowerShell, same machine, same minute)
- `Get-NetFirewallProfile`: Domain/Private/Public all `Enabled = True` (matches `firewall.*` = ENABLED).
- `Get-MpComputerStatus`: `AMServiceEnabled=False`, `AntivirusEnabled=False`, `RealTimeProtectionEnabled=False`, `AMRunningMode=Not running`, `AntivirusSignatureAge=65535` (the raw flags are False and the mode is `Not running`, which `meta-sec` reports as PASSIVE because WSC says another AV is healthy).
- `root/SecurityCenter2 AntiVirusProduct`: Windows Defender and a third-party endpoint product are registered (the third-party product is the active AV). This is why WSC reports GOOD while Defender is not running: the two checks answer different questions. Before the review fixes the tool reported these Defender checks as DISABLED; that was misleading when another AV is active, so they are now PASSIVE (posture NOT_APPLICABLE). `signature_age_days` is omitted when WMI returns the 65535 "not available" sentinel.

## What was NOT tested
- Windows Server (no lab on this machine). Expected: WSC returns an error and maps to UNKNOWN/NOT_SUPPORTED; unverified.
- Elevated (administrator) execution.
- Machine where the Defender WMI namespace is absent (NOT_SUPPORTED path is covered only by the pure classification unit tests, not a real OS).
- Firewall comparison on a second machine (acceptance item 6 asks for two).

## Raw output
```text
### meta-sec --help
--- stdout ---
META Security Agent v0.1.0 (Standalone, read-only)
Usage:
  meta-sec status [--json]   Observe firewall and antivirus state
  meta-sec --version
  meta-sec --help
Exit codes: 0 ok, 1 violation (audit, future), 2 command/engine error, 3 incomplete observation
--- exit code: 0
--- stderr ---

### meta-sec --version
--- stdout ---
0.1.0
--- exit code: 0
--- stderr ---

### meta-sec status
--- stdout ---
META Security Agent v0.1.0 | Standalone | Read-only
Host: <REDACTED-HOST>
Platform: windows 10.0.26200 (client)
Observed: 2026-10-30T04:35:12Z
firewall.domain                             ENABLED
firewall.private                            ENABLED
firewall.public                             ENABLED
antivirus.windows_security_center           GOOD
antivirus.defender.antivirus                PASSIVE        [am_running_mode=Not running] [reason=defender not running; Windows Security Center reports another healthy AV] [am_service_enabled=false] [am_product_version=4.18.26030.3011]
antivirus.defender.realtime_protection      PASSIVE        [reason=defender not running; Windows Security Center reports another healthy AV] [tamper_protected=false]
Overall: OBSERVED (an observation summary, not an antivirus protection verdict)
--- exit code: 0
--- stderr ---

### meta-sec status --json
--- stdout ---
{"schema_version":1,"product":"META Security Agent","version":"0.1.0","mode":"standalone","hostname":"<REDACTED-HOST>","observed_at_utc":"2026-10-30T04:35:12Z","platform":{"os":"windows","version":"10.0.26200","kind":"client"},"checks":[{"check_id":"firewall.domain","name":"firewall.domain","observed_at_utc":"2026-10-30T04:35:12Z","state":"ENABLED","posture":"OK","source":"INetFwPolicy2","error_code":"","error":"","evidence":{}},{"check_id":"firewall.private","name":"firewall.private","observed_at_utc":"2026-10-30T04:35:12Z","state":"ENABLED","posture":"OK","source":"INetFwPolicy2","error_code":"","error":"","evidence":{}},{"check_id":"firewall.public","name":"firewall.public","observed_at_utc":"2026-10-30T04:35:12Z","state":"ENABLED","posture":"OK","source":"INetFwPolicy2","error_code":"","error":"","evidence":{}},{"check_id":"antivirus.windows_security_center","name":"antivirus.windows_security_center","observed_at_utc":"2026-10-30T04:35:12Z","state":"GOOD","posture":"OK","source":"WscGetSecurityProviderHealth","error_code":"","error":"","evidence":{}},{"check_id":"antivirus.defender.antivirus","name":"antivirus.defender.antivirus","observed_at_utc":"2026-10-30T04:35:12Z","state":"PASSIVE","posture":"NOT_APPLICABLE","source":"WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpComputerStatus","error_code":"","error":"","evidence":{"am_running_mode":"Not running","reason":"defender not running; Windows Security Center reports another healthy AV","am_service_enabled":"false","am_product_version":"4.18.26030.3011"}},{"check_id":"antivirus.defender.realtime_protection","name":"antivirus.defender.realtime_protection","observed_at_utc":"2026-10-30T04:35:12Z","state":"PASSIVE","posture":"NOT_APPLICABLE","source":"WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpComputerStatus","error_code":"","error":"","evidence":{"reason":"defender not running; Windows Security Center reports another healthy AV","tamper_protected":"false"}}],"attention":[],"overall":"OBSERVED"}
--- exit code: 0
--- stderr ---

### meta-sec status --bogus
--- stdout ---
--- exit code: 2
--- stderr ---
meta-sec: unexpected argument: --bogus
META Security Agent v0.1.0 (Standalone, read-only)
Usage:
  meta-sec status [--json]   Observe firewall and antivirus state
  meta-sec --version
  meta-sec --help
Exit codes: 0 ok, 1 violation (audit, future), 2 command/engine error, 3 incomplete observation

### meta-sec frobnicate
--- stdout ---
--- exit code: 2
--- stderr ---
meta-sec: unknown command: frobnicate
META Security Agent v0.1.0 (Standalone, read-only)
Usage:
  meta-sec status [--json]   Observe firewall and antivirus state
  meta-sec --version
  meta-sec --help
Exit codes: 0 ok, 1 violation (audit, future), 2 command/engine error, 3 incomplete observation

### meta-sec 
--- stdout ---
--- exit code: 2
--- stderr ---
meta-sec: missing command
META Security Agent v0.1.0 (Standalone, read-only)
Usage:
  meta-sec status [--json]   Observe firewall and antivirus state
  meta-sec --version
  meta-sec --help
Exit codes: 0 ok, 1 violation (audit, future), 2 command/engine error, 3 incomplete observation

```
