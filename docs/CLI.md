# CLI contract

Current implementation (MVP-0 status, MVP-1 audit):
```powershell
meta-sec.exe --help
meta-sec.exe --version
meta-sec.exe status
meta-sec.exe status --json
meta-sec.exe audit [--json]
```

Exit codes today: `0` observation complete (`OBSERVED` or `OBSERVED_WITH_ISSUES`), `2` bad arguments or engine failure (diagnostic on stderr, nothing on stdout), `3` incomplete observation (`INCOMPLETE`). `status` never returns 1; `1` is returned by `audit` for a confirmed FAIL (see below).

### `status --json` (schema_version 1)
```json
{"schema_version":1,"product":"META Security Agent","version":"0.1.0","mode":"standalone",
 "hostname":"...","observed_at_utc":"2026-10-30T04:24:08Z",
 "platform":{"os":"windows","version":"10.0.26200","kind":"client"},
 "checks":[{"check_id":"firewall.public","name":"firewall.public",
            "observed_at_utc":"...","state":"ENABLED","posture":"OK",
            "source":"INetFwPolicy2","error_code":"","error":"","evidence":{}}],
 "attention":[],
 "overall":"OBSERVED"}
```
- One line on stdout; strings are valid UTF-8 (invalid bytes become U+FFFD).
- `state`: `ENABLED DISABLED GOOD POOR SNOOZE NOT_MONITORED PASSIVE UNKNOWN NOT_SUPPORTED`. `PASSIVE` = observed, but Defender is not the primary engine (AMRunningMode is not `Normal`, or `Not running` while Windows Security Center reports a healthy AV); `evidence.reason` says which. `UNKNOWN` = the call failed; `NOT_SUPPORTED` = the API/provider does not exist on this machine. Neither is ever converted to a positive state.
- `error_code` is empty on success, otherwise `HRESULT:0x........` (or `NO_INSTANCE`, `PROPERTY_UNAVAILABLE:<prop>`). `name` and `error` duplicate `check_id` and `error_code` for compatibility with the MVP-0 skeleton and may be removed in a future schema version.
- Check ids: `firewall.domain|private|public`, `antivirus.windows_security_center`, `antivirus.defender.antivirus`, `antivirus.defender.realtime_protection`. `evidence` carries extra context such as `am_running_mode`, `signature_age_days`.
- `posture` (additive, per check): `OK` (ENABLED, GOOD), `ATTENTION` (DISABLED, POOR, SNOOZE, NOT_MONITORED), `NOT_APPLICABLE` (PASSIVE), `UNKNOWN` (UNKNOWN, NOT_SUPPORTED). A disabled setting is observed, but it is never presented as fine.
- `attention` (additive, top level): `check_id`s whose posture is `ATTENTION`; `[]` when none.
- `overall`: `INCOMPLETE` if any check is UNKNOWN, NOT_SUPPORTED or NOT_MONITORED (exit 3); else `OBSERVED_WITH_ISSUES` if `attention` is non-empty; else `OBSERVED`. Both OBSERVED values exit 0: `status` observes, it does not judge. Exit 1 belongs to `audit`. Consumers must read `attention`/`posture`, not just the exit code.
- Non-HRESULT `error_code` values: `TIMEOUT` (WMI query timed out), `NO_INSTANCE` (query returned nothing), `PROPERTY_UNAVAILABLE:<prop>` (property missing or wrong type), `UNRECOGNIZED_RUNNING_MODE:<sanitized value>` (Defender `AMRunningMode` is empty or not one of Normal, Passive, Passive mode, SxS Passive Mode, EDR Block Mode, Not running; matching is case-sensitive and fails closed to `UNKNOWN`). All of them come with state `UNKNOWN`.

## `audit` (MVP-1)

```powershell
meta-sec.exe audit
meta-sec.exe audit --json
```

`audit` is read-only like `status`. It judges what `status` observes (plus the list of registered antivirus products from Security Center) against versioned rules. It never changes a setting; `remediation` is text for a human.

Exit codes: `0` no rule failed and none is unknown; `1` at least one rule FAILed (confirmed violation); `2` bad arguments or engine failure; `3` no FAIL, but at least one rule is UNKNOWN (observation insufficient). **Precedence: 1 outranks 3.** A confirmed violation is actionable and must not be hidden by an unrelated unknown; the `summary` and `rules[].result` still show the unknowns. Exit 0 therefore means "no violation found and nothing unobserved", never "protected".

### Rules (all `rule_version` 1)
| rule_id | Checks | Severity if FAIL | Inputs |
|---|---|---|---|
| `META-FW-001` / `002` / `003` | Firewall enabled for Domain / Private / Public | HIGH | `firewall.*` (`INetFwPolicy2`). Profile on/off only; effective rules are not audited |
| `META-AV-001` | Security Center aggregate AV health is GOOD | HIGH | `antivirus.windows_security_center`. POOR/SNOOZE = FAIL; NOT_MONITORED/failure = UNKNOWN |
| `META-AV-002` | At least one AV engine is active | HIGH | Defender checks plus `AntiVirusProduct` list. See below |
| `META-AV-003` | Defender real-time protection on, when Defender is the primary engine (`AMRunningMode` = `Normal`) | HIGH | Defender checks. Passive / not running = NOT_APPLICABLE; mode unknown = UNKNOWN |
| `META-AV-004` | Defender signature age <= **3 days** (`kSignatureMaxAgeDays`) | MEDIUM | `AntivirusSignatureAge`, only when Defender is the primary engine. Otherwise NOT_APPLICABLE (not primary, or no Defender provider) or UNKNOWN (unreadable, missing, malformed or negative age, mode unknown) |

The 3-day threshold is a documented constant: Defender intelligence is published several times a day, so 3 days tolerates a long weekend or a switched-off laptop while 4+ days means updates are not arriving. Changing it requires a `rule_version` bump. Third-party signature freshness is **not** judged: the only source (a bit in `productState`) is undocumented.

`META-AV-002` decision order: (a) Defender antivirus and real-time both ENABLED -> PASS. (b) Security Center list observed: if Defender is the primary engine and reads off while some entry reads ON (likely Defender's own registration) -> UNKNOWN; otherwise any product with the ON nibble -> PASS (names the engine; self-reported by the vendor). With no ON product: a product with an unrecognized `productState` -> UNKNOWN; WSC aggregate GOOD (contradiction), or Defender passive with an empty list (contradiction) -> UNKNOWN; an unreadable Defender -> UNKNOWN; otherwise (all products OFF/SNOOZED/EXPIRED or none registered, WSC not GOOD) -> FAIL. (c) List unavailable (Windows Server has no `ROOT\SecurityCenter2` -> `NOT_SUPPORTED`; a failed or timed-out query; or more than 32 entries -> `TRUNCATED`) -> FAIL only when Defender real-time is off and either Defender is the primary engine or Security Center reports POOR/SNOOZE; everything else, including "Defender passive but list unavailable", is UNKNOWN. Known limit: a stale registration left behind by an uninstalled product can still read ON.

`productState` decoding: bits 12..15 = 0 OFF, 1 ON, 2 SNOOZED, 3 EXPIRED; anything else, negative, or above 0xFFFFFF is `UNRECOGNIZED` and never counts as ON. The encoding is widely used but not documented by Microsoft.

### `audit --json` (its own document, `schema_version` 1, `"command":"audit"`)
```json
{"schema_version":1,"command":"audit","product":"META Security Agent","version":"0.1.0","mode":"standalone",
 "hostname":"...","observed_at_utc":"...","platform":{"os":"windows","version":"10.0.26200","kind":"client"},
 "rules":[{"rule_id":"META-FW-001","rule_version":1,"title":"...","result":"PASS","severity":"HIGH",
           "remediation":"...","evidence":{"state":"ENABLED"},
           "provenance":{"check_ids":["firewall.domain"],"sources":["INetFwPolicy2"]}}],
 "summary":{"pass":5,"fail":0,"unknown":0,"not_applicable":2},
 "overall":"NO_FINDINGS"}
```
- `result`: `PASS FAIL UNKNOWN NOT_APPLICABLE`. `severity` is what a FAIL would mean and is reported for every result. `remediation` is present for every rule. An UNKNOWN always has `evidence.reason`.
- `overall`: `FINDINGS` (exit 1), `INCOMPLETE` (exit 3), `NO_FINDINGS` (exit 0).
- `provenance.check_ids` are the `status` check ids (and `av_products`) the verdict depends on; `sources` are the underlying data sources (`INetFwPolicy2`, `WscGetSecurityProviderHealth`, `WMI:ROOT\Microsoft\Windows\Defender:MSFT_MpComputerStatus`, `WMI:ROOT\SecurityCenter2:AntiVirusProduct`).
- `status --json` is unchanged (schema 1 with the `name`/`error` aliases).

Future:
```text
meta-sec watch
meta-sec scan --quick
meta-sec threats list
meta-sec service status
meta-sec policy check
meta-sec fix --dry-run
meta-sec center join
meta-sec center status
meta-sec center leave
meta-center devices list
meta-center alerts list
```

JSON stdout only for `--json`; diagnostics on stderr. Stable schema is described above. Never invent `PROTECTED` from missing observations. Exit: 0 usable read, 1 confirmed audit finding, 2 command error, 3 incomplete observation. Commands with side effects require explicit human approval; no arbitrary remote shell.
