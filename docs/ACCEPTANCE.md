# Acceptance and demonstration contract

## MVP-0 must pass
- [ ] Compile on Windows with documented MSVC and CMake versions.
- [ ] `meta-sec --help` works.
- [ ] `meta-sec status` reports actual hostname and firewall profiles.
- [ ] `meta-sec status --json` parses successfully as JSON.
- [ ] WSC health does not masquerade as Defender-specific realtime protection.
- [ ] Unknown / Windows Server unsupported cases explicitly reported.
- [ ] Non-admin invocation tested; invalid arguments rejected.
- [ ] No network or database required.
- [ ] No changes to firewall, antivirus, filesystem security settings.
- [ ] At least one automated negative test and example redacted output.
- [ ] Windows environment and tested binary SHA captured.

## Every further MVP
- [ ] Real executable demonstration.
- [ ] Evidence on actual supported Windows/Ubuntu system.
- [ ] User-visible goal and precise demonstration command.
- [ ] Expected result and error states.
- [ ] Unit / integration tests and negative security tests.
- [ ] Approval gate for side-effects.
- [ ] Rollback/recovery procedure.
- [ ] Human acceptance recorded.

**No checkbox is pre-checked.** Source upload is not proof that test gates have passed.

## MVP-0 status record (2026-10-30, branch `feat/mvp0-build-defender-tests`)
Boxes above stay unchecked until a human accepts. Evidence so far, details in [evidence/mvp0-win11.md](evidence/mvp0-win11.md):

| Item | Result |
|---|---|
| MSVC/CMake build | PASS on Windows 11 Pro 10.0.26200 (MSVC 19.44, CMake 4.0.2, `/W4 /WX`) |
| `--help` | PASS (exit 0) |
| Real hostname and firewall profiles | PASS, matches `Get-NetFirewallProfile` on one machine |
| `status --json` valid JSON, clean stdout | PASS (checked by CMake's JSON parser in CTest) |
| WSC not presented as Defender state | PASS, separate checks; on the lab machine WSC=GOOD while Defender is PASSIVE (not running, another AV healthy) |
| Unknown / unsupported / attention reported explicitly | PASS in unit tests (156 checks, fakes for every provider decision); not observed on a real OS |
| Non-admin run, invalid arguments | PASS (non-admin session; bad args exit 2 on stderr) |
| Elevated run, Windows Server, second machine | NOT TESTED |
| No network/db, no setting changes | by design (read-only COM/WMI queries); no network code |
| Automated negative test + redacted output + SHA | PASS |
