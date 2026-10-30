# CLI contract

Current implementation (MVP-0):
```powershell
meta-sec.exe --help
meta-sec.exe --version
meta-sec.exe status
meta-sec.exe status --json
```

Exit codes today: `0` observation complete (`OBSERVED` or `OBSERVED_WITH_ISSUES`), `2` bad arguments or engine failure (diagnostic on stderr, nothing on stdout), `3` incomplete observation (`INCOMPLETE`). `1` is reserved for confirmed audit findings (MVP-1).

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
- `overall`: `INCOMPLETE` if any check is UNKNOWN, NOT_SUPPORTED or NOT_MONITORED (exit 3); else `OBSERVED_WITH_ISSUES` if `attention` is non-empty; else `OBSERVED`. Both OBSERVED values exit 0: `status` observes, it does not judge. Exit 1 is reserved for `audit` (MVP-1). Consumers must read `attention`/`posture`, not just the exit code.
- A timed-out WMI query is reported as `UNKNOWN` with `error_code` `TIMEOUT`; an empty result as `NO_INSTANCE`.

Future:
```text
meta-sec audit [--json]
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
