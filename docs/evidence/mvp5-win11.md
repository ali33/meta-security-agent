# MVP-5 evidence: Windows 11 Pro (lab: developer workstation)

Captured 2026-11-02 from branch `feat/mvp5-policy` (from `main` 146e95e). Host name and Windows account are redacted below. No firewall, Defender or antivirus setting was changed; no scan, service or network call was made.

**Headline:** `meta-sec policy check` runs on this machine against the built-in baseline and reports `NO_DRIFT` (5 COMPLIANT, 2 NOT_APPLICABLE, exit 0). **A real configuration drift was never produced on a real machine**: this machine is healthy and the rule is read-only (no setting may be weakened). Drift, INCOMPLETE and every hostile-policy case are proven with fake machine states and crafted files, not with a weakened real OS.

## Environment
| Item | Value |
|---|---|
| OS | Microsoft Windows 11 Pro, 10.0.26200 (client) |
| Compiler | MSVC 19.44 (VS 2022 Build Tools), `/W4 /WX /EHsc /utf-8 /permissive- /sdl /guard:cf`; link `/guard:cf /CETCOMPAT /DEPENDENTLOADFLAG:0x800` |
| Build | CMake 4.0.2, "Visual Studio 17 2022" x64, Release |
| Tests | ctest **46/46** passed: `policy_unit` (**5,379 checks**), `policy_json_roundtrip`, 7 `cli_policy_*` e2e modes, plus all earlier suites unchanged (`core_unit` 180, `audit_unit` 79,909) |
| Elevation | **Non-admin** (elevated run NOT tested) |
| Machine state | Defender `Not running`, Bitdefender the active AV; firewall Domain/Private/Public enabled |
| `meta-sec.exe` SHA256 | `6146BC0797C1E1AD9CBEB233BC731DD714A3E47F480C3E77BE1EEFFB1C2448D0` (working tree at the time of capture, after the review fixes; committed together with this file) |

## Real run, JSON (`policy check --json`, exit 0, stderr empty; excerpt)
```json
{"schema_version":1,"command":"policy check","product":"META Security Agent","version":"0.1.0","mode":"standalone","hostname":"<redacted>","observed_at_utc":"2026-11-02T02:28:45Z","platform":{"os":"windows","version":"10.0.26200","kind":"client"},"policy":{"policy_schema_version":1,"policy_id":"meta-default-baseline","policy_version":1,"source":"built-in"},"rules":[{"rule_id":"META-FW-001",...,"expected":{"result":"PASS"},"observed":{"result":"PASS","evidence":{"profile":"Domain","state":"ENABLED",...}},"verdict":"COMPLIANT",...}, ...],"summary":{"compliant":5,"drift":0,"incomplete":0,"not_applicable":2},"overall":"NO_DRIFT"}
```
Text mode (same run, abridged): `[COMPLIANT] META-FW-001 ... expected: PASS / observed: PASS / why: ... / source: INetFwPolicy2`, `[NOT_APPLICABLE] META-AV-003/004` (Defender is not the primary engine), `Summary: 5 compliant, 0 drift, 0 incomplete, 2 not applicable`, `Overall: NO_DRIFT`.

## What was proven, and how
| Claim | Evidence | Kind |
|---|---|---|
| Public firewall off -> exactly META-FW-003 is DRIFT, others COMPLIANT, exit 1 | `test_end_to_end_drift` (real `run_audit` over a fake machine) | fake state |
| Unobservable rule -> INCOMPLETE, never COMPLIANT; missing rule -> INCOMPLETE; empty audit -> all INCOMPLETE | `test_verdict_table` (invariant sweep: COMPLIANT iff audit PASS), `test_missing_rule_is_incomplete` | unit |
| All rules NOT_APPLICABLE -> INCOMPLETE (exit 3), added after review | `test_missing_rule_is_incomplete` | unit |
| 1 outranks 3; empty report is INCOMPLETE | `test_overall_and_exit` | unit |
| AV-004 policy limit (inclusive, loose and strict, no age -> INCOMPLETE), override explained in `detail` | `test_signature_limit`, `test_end_to_end_drift` | unit |
| Strict parser: ~150 hostile policies rejected (unknown key/rule id, duplicates, wrong types, ranges, comments, trailing text, invalid UTF-8, depth bomb, 10 MiB junk, >64 KiB, 33 rules...) and the at-limit file accepted | `test_parse_hostile`, `test_parse_valid` | unit |
| Path rules (UNC, device, ADS, drive-relative, wildcards, control chars, length) | `test_paths` and `cli_policy_bad_args` | unit + e2e |
| Hostile files on disk each refused for their own reason, exit 2, empty stdout, path not echoed: empty, malformed, not object, unknown key, unknown rule, duplicate rule, bad expect, future schema, trailing junk, depth 200, 70,000 bytes, directory, missing, `NUL`, **junction in the middle of the path** | `cli_policy_bad_files` (expected stderr fragment per file) | e2e on the real binary |
| Valid custom policy honoured (id, version, only its two rules), path never in the report | `cli_policy_file_ok` | e2e |
| `policy default` output is valid JSON and is itself accepted by `--policy-file` | `cli_policy_default` | e2e |
| Read-only, no remediation flag exists (`--fix`, `--apply`, `--dry-run` are errors) | `cli_policy_bad_args`, `test_args` | e2e |
| JSON escaping of hostile host/evidence/source strings and no terminal control characters in text | `policy_json_roundtrip` (CMake's own parser), `test_render` | unit |

## Review
Two independent reviewers (code and security, different agents from the author) examined commit 3a36633. Fixed in the next commit:
- **Security, high-leaning:** the file was opened *before* the network/link check, so a symlink or mapped drive to a share would make Windows contact the share first (confirmed by the reviewer with a symlink to `\\localhost\C$`). Now: drive type checked and every path component checked for reparse points *before* opening; the file is opened as itself; offline/recall (cloud) files refused.
- A policy with only NOT_APPLICABLE rules gave NO_DRIFT/exit 0; now INCOMPLETE/exit 3.
- AV-004 policy limit could give COMPLIANT while the audit said FAIL with no explanation; the detail now states the replaced threshold and the audit's own result (still a design choice, see decisions).
- Missing-rule record had empty title/remediation; filled. E2E tests now assert the specific rejection reason per file.
Not done (reported as limits in SECURITY.md): policy hash / coverage marker, check-then-open race on a directory swapped by a local attacker, `subst` drive pointing at a share.

## What was NOT tested
- A real drift on a real machine (no setting weakened); a real INCOMPLETE on a real OS.
- Elevated run; Windows Server (CI on windows-latest should run the e2e cases, which accept exit 0/1/3).
- A real network share, a mapped drive, a symlink to a UNC path (needs Developer Mode/admin; only the junction case is automated), a cloud placeholder file, `subst`.
- A file growing while it is read (logic present, no test).
- Behaviour when `%TEMP%` itself contains a link (the e2e tests would then be refused by design).
