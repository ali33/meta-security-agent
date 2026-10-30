# CLI contract

Current implementation (MVP-0 status, MVP-1 audit, MVP-2 watch):
```powershell
meta-sec.exe --help
meta-sec.exe --version
meta-sec.exe status
meta-sec.exe status --json
meta-sec.exe audit [--json]
meta-sec.exe watch [--json] [--interval S] [--max-polls N] [--confirm N]
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

## `watch` (MVP-2)

```powershell
meta-sec.exe watch                                  # text lines until Ctrl+C
meta-sec.exe watch --json                           # NDJSON: one JSON object per line
meta-sec.exe watch --json --interval 5 --max-polls 12 --confirm 2
```

`watch` polls the same read-only collectors as `status` and reports **changes**. It never changes a setting, uses no network, and keeps no state between runs (persistence is MVP-4/5).

| Option | Default | Range | Meaning |
|---|---|---|---|
| `--interval S` | 30 | 1..3600 | Seconds between the end of one poll and the start of the next |
| `--max-polls N` | unlimited | 1..1,000,000 | Stop after N polls (deterministic stop for scripts and CI) |
| `--confirm N` | 2 | 1..10 | Debounce: a new value is reported only after N **consecutive** polls show it |
| `--json` | off | | NDJSON instead of text |

Anything else, a missing/non-numeric/out-of-range value or a repeated option exits 2 with a diagnostic on stderr and nothing on stdout.

**Lifecycle.** The first poll is printed once as a `baseline` (all checks and their current state; no history is replayed). Each later poll prints nothing unless a check's confirmed state changed. On exit a final `stopped` line is printed. Ctrl+C, Ctrl+Break and closing the console stop the loop cleanly (the wait is interrupted at once; the `stopped` line has `"reason":"interrupted"`). Idle cost is one blocking wait; CPU is spent only during a poll.

**Exit codes.** `0` stopped normally and the last poll observed everything; `3` stopped normally but the last poll was `INCOMPLETE` (same rule as `status`; e.g. a Windows Server runner where Security Center is `NOT_SUPPORTED`); `2` bad arguments, COM failure, or stdout could not be written (`reason":"output_failed"` is attempted but may not be deliverable). `watch` never returns `1`: judging is `audit`'s job.

**What counts as one change.** The tracked value of a check is its `state` (so `ENABLED -> DISABLED`, `GOOD -> POOR`, `PASSIVE -> ENABLED` are changes; a different `evidence` or `observed_at_utc` alone is not). A change is reported once, when the new state has been seen on `--confirm` consecutive polls; the event's `observed_at_utc` is the confirming poll and `first_observed_at_utc` the first poll that showed it. With the default interval 30 s and confirm 2, a change is reported 30..60 s after it happened. A value that reverts before confirmation (flapping, one-poll glitch) is dropped silently; a value that alternates faster than `--confirm` polls is therefore never reported. The pending candidate restarts if the observation becomes a third value.

**UNKNOWN is not "turned off".** A check that stops being readable (`UNKNOWN`/`NOT_SUPPORTED`) after `--confirm` polls is an `observation_lost` event, never a `change` to a disabled state; its later recovery is `observation_restored`. A one-poll read error produces no event. Every transition of `UNKNOWN` to a state, including back to the old one, is reported, because the observation gap itself is information.

### `watch --json` events (`schema_version` 1, `"command":"watch"`)
Common fields: `schema_version`, `command`, `event`, `observed_at_utc`.

- `baseline` (always first): `product, version, mode, hostname, platform{}, interval_seconds, confirm_polls, checks[]` where each check has `check_id, state, posture, source, error_code, evidence{}` (same meaning as `status`).
- `change`, `observation_lost`, `observation_restored`, `check_added`, `check_removed`: `first_observed_at_utc, check_id, from, to, from_posture, to_posture, confirmations, source, error_code, evidence{}`. `from` is `null` for `check_added`, `to` is `null` for `check_removed`; `evidence`/`source`/`error_code` describe the new value (the last seen value for a removal). `confirmations >= confirm_polls`.
- `stopped` (always last): `reason` (`max_polls | interrupted | output_failed`), `polls`, `events` (count of non-baseline, non-stopped lines).

```json
{"schema_version":1,"command":"watch","event":"change","observed_at_utc":"2026-10-30T00:01:00Z","first_observed_at_utc":"2026-10-30T00:00:30Z","check_id":"firewall.public","from":"ENABLED","to":"DISABLED","from_posture":"OK","to_posture":"ATTENTION","confirmations":2,"source":"INetFwPolicy2","error_code":"","evidence":{}}
```
Text mode prints the same information one line per event (`<utc> [CHANGE] firewall.public: ENABLED -> DISABLED (ATTENTION)`).

Future:
```text
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
