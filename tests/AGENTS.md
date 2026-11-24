# AGENTS.md

These instructions apply to `tests/` and its descendants. Read the repository [AGENTS.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/AGENTS.md), [AI_POLICY.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/AI_POLICY.md) and the local [AI_POLICY.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/tests/AI_POLICY.md) before working here. The root requirements remain mandatory; report conflicts and do not weaken them.

## Regression tests

- Use existing pytest fixtures, async mocks and aresponses conventions. Mock external requests; routine tests must not depend on live credentials or provider availability.
- Use synthetic or sanitized fixtures and update the actual Syrupy snapshots consumed by pytest. Never replace an assertion merely to make a failure disappear.
- Verify outgoing GraphQL selection and variables as well as parsed results. Cover missing versus null, empty, zero, unknown values, malformed payloads and multiple-device isolation where relevant.
- Assert exception types and privacy-safe diagnostics; use deterministic event barriers for concurrency and preserve cancellation behavior.
- Run targeted tests first, then the applicable full suite and root quality checks. Report actual results and distinguish fixture, lint, typing and runtime failures.
