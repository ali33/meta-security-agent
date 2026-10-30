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
