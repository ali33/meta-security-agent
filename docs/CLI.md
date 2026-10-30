# CLI contract

Current implementation (MVP-0):
```powershell
meta-sec.exe --help
meta-sec.exe status
meta-sec.exe status --json
```

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

JSON stdout only for `--json`; diagnostics on stderr. Stable schema includes check name, state, source, error, version and mode. Never invent `PROTECTED` from missing observations. Exit: 0 usable read, 1 confirmed audit finding, 2 command error, 3 incomplete observation. Commands with side effects require explicit human approval; no arbitrary remote shell.
