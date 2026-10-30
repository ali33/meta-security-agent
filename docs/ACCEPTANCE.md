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
