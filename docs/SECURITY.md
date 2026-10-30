# Security baseline — release blocker

Required chain: Agent -> unique identity -> least privilege -> sandbox -> action log -> policy gate -> human approval -> rollback.

1. Default READ-ONLY / DENY-BY-DEFAULT: status/audit/watch do not change configuration.
2. Device identity/credential unique per endpoint; service permissions restricted.
3. No API keys, private keys, tokens or user secrets in code, command output, logs or prompts.
4. Validate every input, output schema, policy and executable; fail closed on uncertainty.
5. Remote execution never offers arbitrary shell or scripts; typed allowlisted operations only.
6. Scan, configuration write, delete, deploy, admin and firewall changes require explicit human approval and auditable intent.
7. Isolation/sandbox, blast-radius limit, dry-run, canary, kill switch and rollback before side-effects.
8. Keep last known valid local security posture when disconnected; no remote fail-open.
9. Protect audit logs against modification; redact sensitive fields and log decisions.
10. Public GitHub: no internal IPs, private topology, credentials, proprietary payloads or production configuration.
11. CI compile/test only; never auto-deploy production.

## Approval gate for `scan --quick` (MVP-3)
`scan` is the only side effect. Controls (details in [CLI.md](CLI.md)):
- **Gate first:** Defender must be the primary engine (`AMRunningMode` == `Normal`); anything unknown is refused (fail closed) and nothing is prompted.
- **Human approval on a real console:** exact phrase typed at a prompt; stdin must be a console input handle and stderr a console. Pipes, files, `NUL`, closed handles, EOF, read errors and wrong text are all refusals. No bypass flag exists. Any future automation switch is a separate, human-approved decision.
- **Recorded actor:** the Windows account and UTC time of approval are part of the output; shared evidence must redact them.
- **Re-check before acting:** the gate is evaluated again after approval, immediately before `Start`.
- **Minimal scope:** one quick scan; no path argument, no full/custom scan, no remediation, quarantine or configuration change; no network.
- **Honest outcome:** success is claimed only when Defender's own timestamps show a new completed scan; access denied, errors, timeout and Ctrl+C are reported as such. The tool cannot cancel a scan it started.
- **Not a boundary against same-user code:** a process already running as the user can call the same WMI method; the gate defends against accidental and scripted invocation of *this tool*, not against malware with the user's rights.
