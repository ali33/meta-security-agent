# CLI contract

Current implementation (MVP-0):
```powershell
meta-sec.exe --help
meta-sec.exe --version
meta-sec.exe status
meta-sec.exe status --json
```

Exit codes today: `0` observation complete (`OBSERVED`), `2` bad arguments or engine failure (diagnostic on stderr, nothing on stdout), `3` incomplete observation (`INCOMPLETE`). `1` is reserved for confirmed audit findings (MVP-1).

### `status --json` (schema_version 1)
```json
{"schema_version":1,"product":"META Security Agent","version":"0.1.0","mode":"standalone",
 "hostname":"...","observed_at_utc":"2026-10-30T04:24:08Z",
 "platform":{"os":"windows","version":"10.0.26200","kind":"client"},
 "checks":[{"check_id":"firewall.public","name":"firewall.public",
            "observed_at_utc":"...","state":"ENABLED","source":"INetFwPolicy2",
            "error_code":"","error":"","evidence":{}}],
 "overall":"OBSERVED"}
```
- One line on stdout; strings are valid UTF-8 (invalid bytes become U+FFFD).
- `state`: `ENABLED DISABLED GOOD POOR SNOOZE NOT_MONITORED UNKNOWN NOT_SUPPORTED`. `UNKNOWN` = the call failed; `NOT_SUPPORTED` = the API/provider does not exist on this machine. Neither is ever converted to a positive state.
- `error_code` is empty on success, otherwise `HRESULT:0x........` (or `NO_INSTANCE`, `PROPERTY_UNAVAILABLE:<prop>`). `name` and `error` duplicate `check_id` and `error_code` for compatibility with the MVP-0 skeleton and may be removed in a future schema version.
- Check ids: `firewall.domain|private|public`, `antivirus.windows_security_center`, `antivirus.defender.antivirus`, `antivirus.defender.realtime_protection`. `evidence` carries extra context such as `am_running_mode`, `signature_age_days`.
- `overall` is `OBSERVED` only when every check yielded a real observation, else `INCOMPLETE`.

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
