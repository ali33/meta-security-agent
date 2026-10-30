# MVP-1 evidence: Windows 11 Pro (lab: developer workstation)

Captured 2026-10-30 from commit `5f739fb` (branch `feat/mvp1-audit`, stacked on `feat/mvp0-build-defender-tests` incl. the run-time `wscapi.dll` load). Hostname replaced with `<REDACTED-HOST>`; nothing else edited.

## Environment
| Item | Value |
|---|---|
| OS | Microsoft Windows 11 Pro, 10.0.26200 (client) |
| Compiler | MSVC 19.44 (VS 2022 Build Tools), `/W4 /WX /EHsc /utf-8 /permissive- /sdl /guard:cf` |
| Build system | CMake 4.0.2, MSBuild 17.14, generator "Visual Studio 17 2022" x64 |
| Commands | `cmake -S . -B build -A x64`, `cmake --build build --config Release`, `ctest --test-dir build -C Release` |
| Tests | ctest 14/14 passed: `core_unit` (180 checks), `audit_unit` (79,909 checks incl. an invariant sweep over 4x4x6x9x6 input combinations), `json_roundtrip`, `audit_json_roundtrip`, and 10 end-to-end CLI cases (`audit`, `audit --json`, `audit --bogus` among them) |
| Elevation | **Non-admin** (`IsInRole(Administrator)` = False). Elevated run: NOT tested |
| `meta-sec.exe` SHA256 | `62d94fff3e44edd1758e59ed9094572f160cc6a06f8d81de029b696c6d4482c7` |

## Independent cross-check (read-only PowerShell, same machine, same session)
- `Get-NetFirewallProfile`: Domain/Private/Public `Enabled = True` -> META-FW-001..003 PASS.
- `Get-CimInstance root/SecurityCenter2 AntiVirusProduct`: `Windows Defender` productState 393472 (`0x60100`, on/off nibble 0) and the third-party endpoint product 266240 (`0x41000`, nibble 1). This matches the decoding in `av_activity` and the audit's `active_engine` evidence.
- The e2e test `cli_audit_json` additionally re-runs `status --json` and checks that each firewall rule result follows the observed profile state.

## Lab profiles (acceptance: "controlled secure/insecure profiles produce correct findings")
**PARTIAL.** This machine is non-admin and the tool is read-only by rule, so no firewall/Defender/AV setting was weakened. Secure and insecure profiles were built as fixtures and loaded into the core (`test_lab_profiles`, `test_active_av`, `test_signature_age` in `tests/test_audit.cpp`). They prove the rule logic, including FAIL for: a disabled profile, WSC POOR/SNOOZE, no active engine, Defender real-time off while primary, signatures older than 3 days. They do **not** prove the Windows data sources report those states on a real weakened machine. The run below is the secure case on a real OS: no real FAIL has been observed.

## What was NOT tested
- A real machine with a weakened configuration (firewall off, AV off/snoozed, old Defender signatures); a Defender-primary machine (here Defender is not running, so META-AV-003/004 are NOT_APPLICABLE on the real OS).
- Windows Server / absence of `ROOT\SecurityCenter2` (the NOT_SUPPORTED path is covered only by unit tests with fakes).
- Elevated execution; a second machine; list truncation (`TRUNCATED`) on a real OS.
- `productState` encoding is undocumented by Microsoft; stale registrations of uninstalled products may read ON.

## Raw output (non-admin)
```text
### meta-sec audit
--- stdout ---
META Security Agent v0.1.0 | Standalone | Read-only | Audit
Host: <REDACTED-HOST>
Platform: windows 10.0.26200 (client)
Observed: 2026-10-30T05:10:55Z
[PASS] META-FW-001 (v1, HIGH) Windows Firewall is enabled for the Domain profile
      profile: Domain
      state: ENABLED
      note: profile on/off only; effective rules are not audited
[PASS] META-FW-002 (v1, HIGH) Windows Firewall is enabled for the Private profile
      profile: Private
      state: ENABLED
      note: profile on/off only; effective rules are not audited
[PASS] META-FW-003 (v1, HIGH) Windows Firewall is enabled for the Public profile
      profile: Public
      state: ENABLED
      note: profile on/off only; effective rules are not audited
[PASS] META-AV-001 (v1, HIGH) Windows Security Center reports antivirus health GOOD
      state: GOOD
      note: aggregate of all registered antivirus products, not Defender-specific
[PASS] META-AV-002 (v1, HIGH) At least one antivirus engine is active
      defender_antivirus: PASSIVE
      defender_realtime: PASSIVE
      am_running_mode: Not running
      registered_products_source: OBSERVED
      registered_products: 2
      active_engine: Bitdefender Endpoint Security Tools Chống Malware
      note: registration is self-reported by the product via Security Center
[NOT_APPLICABLE] META-AV-003 (v1, HIGH) Defender real-time protection is on when Defender is the primary engine
      am_running_mode: Not running
      reason: Defender is not the primary engine; see META-AV-002
[NOT_APPLICABLE] META-AV-004 (v1, MEDIUM) Defender signatures are at most 3 days old
      threshold_days: 3
      am_running_mode: Not running
      reason: Defender is not the primary engine; its signature age says nothing about the active engine
Summary: 5 pass, 0 fail, 0 unknown, 2 not applicable
Overall: NO_FINDINGS (an audit of OS settings, not a malware scan or a protection guarantee)
--- exit code: 0
--- stderr ---

### meta-sec audit --json
--- stdout ---
{"schema_version":1,"command":"audit","product":"META Security Agent","version":"0.1.0","mode":"standalone","hostname":"<REDACTED-HOST>","observed_at_utc":"2026-10-30T05:10:56Z","platform":{"os":"windows","version":"10.0.26200","kind":"client"},"rules":[{"rule_id":"META-FW-001","rule_version":1,"title":"Windows Firewall is enabled for the Domain profile","result":"PASS","severity":"HIGH","remediation":"Turn the profile on in Windows Security > Firewall & network protection, or ask an administrator (e.g. Set-NetFirewallProfile -Profile <Domain|Private|Public> -Enabled True). If a Group Policy or another firewall manages it, fix it there.","evidence":{"profile":"Domain","state":"ENABLED","note":"profile on/off only; effective rules are not audited"},"provenance":{"check_ids":["firewall.domain"],"sources":["INetFwPolicy2"]}},{"rule_id":"META-FW-002","rule_version":1,"title":"Windows Firewall is enabled for the Private profile","result":"PASS","severity":"HIGH","remediation":"Turn the profile on in Windows Security > Firewall & network protection, or ask an administrator (e.g. Set-NetFirewallProfile -Profile <Domain|Private|Public> -Enabled True). If a Group Policy or another firewall manages it, fix it there.","evidence":{"profile":"Private","state":"ENABLED","note":"profile on/off only; effective rules are not audited"},"provenance":{"check_ids":["firewall.private"],"sources":["INetFwPolicy2"]}},{"rule_id":"META-FW-003","rule_version":1,"title":"Windows Firewall is enabled for the Public profile","result":"PASS","severity":"HIGH","remediation":"Turn the profile on in Windows Security > Firewall & network protection, or ask an administrator (e.g. Set-NetFirewallProfile -Profile <Domain|Private|Public> -Enabled True). If a Group Policy or another firewall manages it, fix it there.","evidence":{"profile":"Public","state":"ENABLED","note":"profile on/off only; effective rules are not audited"},"provenance":{"check_ids":["firewall.public"],"sources":["INetFwPolicy2"]}},{"rule_id":"META-AV-001","rule_version":1,"title":"Windows Security Center reports antivirus health GOOD","result":"PASS","severity":"HIGH","remediation":"Open Windows Security > Virus & threat protection and resolve the warning: turn the antivirus back on, update its signatures, or end the snooze.","evidence":{"state":"GOOD","note":"aggregate of all registered antivirus products, not Defender-specific"},"provenance":{"check_ids":["antivirus.windows_security_center"],"sources":["WscGetSecurityProviderHealth"]}},{"rule_id":"META-AV-002","rule_version":1,"title":"At least one antivirus engine is active","result":"PASS","severity":"HIGH","remediation":"Enable real-time protection in Windows Security (Virus & threat protection), or install and activate an antivirus product. Ask an administrator if a policy prevents it.","evidence":{"defender_antivirus":"PASSIVE","defender_realtime":"PASSIVE","am_running_mode":"Not running","registered_products_source":"OBSERVED","registered_products":"2","active_engine":"Bitdefender Endpoint Security Tools Chống Malware","note":"registration is self-reported by the product via Security Center"},"provenance":{"check_ids":["antivirus.defender.antivirus","antivirus.defender.realtime_protection","antivirus.windows_security_center","av_products"],"sources":["WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpComputerStatus","WscGetSecurityProviderHealth","WMI:ROOT\\SecurityCenter2:AntiVirusProduct"]}},{"rule_id":"META-AV-003","rule_version":1,"title":"Defender real-time protection is on when Defender is the primary engine","result":"NOT_APPLICABLE","severity":"HIGH","remediation":"Turn on Real-time protection in Windows Security > Virus & threat protection > Manage settings, or ask an administrator if a policy blocks it.","evidence":{"am_running_mode":"Not running","reason":"Defender is not the primary engine; see META-AV-002"},"provenance":{"check_ids":["antivirus.defender.antivirus","antivirus.defender.realtime_protection"],"sources":["WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpComputerStatus"]}},{"rule_id":"META-AV-004","rule_version":1,"title":"Defender signatures are at most 3 days old","result":"NOT_APPLICABLE","severity":"MEDIUM","remediation":"Update protection intelligence: Windows Security > Virus & threat protection > Protection updates > Check for updates, and make sure Windows Update can reach Microsoft.","evidence":{"threshold_days":"3","am_running_mode":"Not running","reason":"Defender is not the primary engine; its signature age says nothing about the active engine"},"provenance":{"check_ids":["antivirus.defender.antivirus"],"sources":["WMI:ROOT\\Microsoft\\Windows\\Defender:MSFT_MpComputerStatus"]}}],"summary":{"pass":5,"fail":0,"unknown":0,"not_applicable":2},"overall":"NO_FINDINGS"}
--- exit code: 0
--- stderr ---

### meta-sec audit --bogus
--- stdout ---
--- exit code: 2
--- stderr ---
meta-sec: unexpected argument: --bogus
META Security Agent v0.1.0 (Standalone, read-only)
Usage:
  meta-sec status [--json]   Observe firewall and antivirus state
  meta-sec audit [--json]    Check settings against rules (PASS/FAIL/UNKNOWN)
  meta-sec --version
  meta-sec --help
Exit codes: 0 ok, 1 audit violation, 2 command/engine error, 3 incomplete observation

### meta-sec status
--- stdout ---
META Security Agent v0.1.0 | Standalone | Read-only
Host: <REDACTED-HOST>
Platform: windows 10.0.26200 (client)
Observed: 2026-10-30T05:10:57Z
firewall.domain                             ENABLED
firewall.private                            ENABLED
firewall.public                             ENABLED
antivirus.windows_security_center           GOOD
antivirus.defender.antivirus                PASSIVE        [am_running_mode=Not running] [reason=defender not running; Windows Security Center reports another healthy AV] [am_service_enabled=false] [am_product_version=4.18.26030.3011]
antivirus.defender.realtime_protection      PASSIVE        [reason=defender not running; Windows Security Center reports another healthy AV] [tamper_protected=false]
Overall: OBSERVED (an observation summary, not an antivirus protection verdict)
--- exit code: 0
--- stderr ---

```
