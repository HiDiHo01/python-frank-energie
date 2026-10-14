# AGENTS.md

## Repository purpose

This repository contains `python-frank-energie`, an asynchronous Python client library for communicating with Frank Energie. It is a reusable library used by Home Assistant and related automation projects.

## Required policy

- Read [`AI_POLICY.md`](AI_POLICY.md) before making changes and follow it.
- AI-generated or AI-refactored changes require human review before merge.
- Never invent Frank Energie API behavior, GraphQL fields, response semantics, or device behavior. Verify assumptions against the existing implementation, tests, or documented responses.
- Never include credentials, tokens, account details, or other private data in code, logs, tests, issues, or pull requests.
- Pull requests involving AI-assisted work must disclose that use and summarize the AI-assisted changes, as required by `AI_POLICY.md`.

## Working practices

- Inspect the relevant source, tests, callers, repository instructions, and configuration before changing behavior.
- Prefer the smallest complete change that fixes the underlying problem.
- Preserve existing public API behavior unless a breaking change is explicitly required and documented.
- Treat this repository as a standalone Python library. Do not add Home Assistant dependencies or use Home Assistant-only helpers in library code.
- Keep changes consistent with the existing module boundaries, naming, data models, and error-handling conventions.
- Do not add speculative fallbacks that hide malformed or unexpected API responses.
- Update tests and documentation when behavior or the public API changes.
- Before proposing dependency or packaging changes, inspect `pyproject.toml`, `poetry.lock`, and the affected consumers where available. Consider runtime, development, and downstream compatibility.

## Python and implementation standards

### Python version compatibility

- The library's current declared minimum is Python **3.12**, as specified by `pyproject.toml`. Treat that file as the source of truth and re-check it before changing compatibility assumptions.
- Keep the `requires-python`/Poetry Python constraint, syntax, standard-library APIs, dependencies, and CI matrix aligned with the minimum Python version the library explicitly supports.
- Do not automatically raise the library's minimum Python version to match Home Assistant Core: this repository is HA-independent, and its compatibility policy must be based on the library's own consumers and dependency constraints.
- When the library is used by a Home Assistant integration, verify the target Core release's Python requirement (including `requires-python` in that exact Core release's `pyproject.toml`) and ensure the library remains compatible with the integration's supported Python range.
- For Home Assistant Core 2026.10 development, the observed Core requirement is Python **3.14.2 or newer**. This is a release-specific reference, not a permanent requirement for this library; re-check the target release rather than relying on memory.
- Keep CI versions within the declared support range and test the minimum supported Python version as well as the primary supported version where practical. Do not claim compatibility with a Python version that CI, dependencies, or source syntax do not support.
- Before relying on a newer language feature or API, verify it is available on Python 3.12, or explicitly justify and coordinate a minimum-version change across metadata, dependencies, CI, documentation, and consumers.

### Implementation standards

- Use modern Python syntax, precise type hints, and `snake_case` names.
- Add clear docstrings to modules, classes, methods, and public functions, following the surrounding code's conventions.
- Prefer built-in generic types such as `list[str]` and `dict[str, object]`; do not introduce legacy `typing.List` or `typing.Dict`.
- Use asynchronous I/O for network operations. Do not block the event loop with synchronous network or file I/O.
- Prefer the standard-library `asyncio.timeout()` for timeout management when the project's minimum Python version is Python 3.11 or later. Do not add or use `async-timeout` solely for timeout handling when `asyncio.timeout()` is available. Preserve compatibility with the declared minimum Python version and catch `TimeoutError` outside the timeout context manager.
- Apply explicit timeouts to network operations and handle cancellation correctly. Do not swallow `asyncio.CancelledError`.
- Use timezone-aware datetimes; avoid naive timestamps and deprecated datetime APIs.
- Use lazy `%` formatting in logging calls.
- Validate external input and API data at appropriate boundaries. Raise descriptive, domain-appropriate errors while preserving useful exception context.
- Handle missing, `None`, malformed, and unexpected API values deliberately. Do not silently reinterpret invalid data as valid defaults without evidence from the API contract.
- For authentication and JWT handling, verify signatures using the expected trusted key and an explicit allowed-algorithm list. Do not disable signature verification for untrusted tokens. Validate relevant claims and expiry according to the actual authentication contract; add tests for invalid signatures and malformed, missing, or expired claims as applicable.
- Keep imports used, avoid dead code, and maintain consistent exception handling.
- Do not add dependencies unless they are necessary and justified.

## Tests and quality checks

Inspect `pyproject.toml`, `poetry.lock`, `.pre-commit-config.yaml`, and the applicable files under `.github/workflows/` before deciding which checks apply. Keep local instructions aligned with those configurations when they change.

Run the relevant tests and checks in the Poetry environment. The repository workflows currently configure pytest with coverage, Ruff, mypy, Poetry lock validation, and a pre-commit matrix that includes formatting, documentation, YAML/TOML/JSON, spelling, security, and unused-code checks. Confirm the current workflow definitions rather than assuming every check runs for every event.

Useful local commands include:

```bash
poetry run pytest tests
poetry run ruff check .
poetry run mypy python_frank_energie
poetry check --lock
poetry run pre-commit run --all-files
```

- Run the checks relevant to the changed files and behavior; run the full applicable suite for changes with broad impact, authentication, shared models, or public API behavior.
- Add focused regression tests for bug fixes, including relevant `None`, missing-field, malformed-response, authentication, expiry, and boundary cases where applicable.
- Use mocked API responses or sanitized fixtures for routine tests; do not depend on live Frank Energie services or real credentials for deterministic unit tests.
- Keep tests deterministic and isolated. Do not weaken assertions, coverage, linting, typing, or security checks merely to obtain a passing result.
- Investigate failures introduced by the change. Distinguish pre-existing failures from regressions using evidence.
- If a check cannot be run, state that clearly in the pull request. Report the actual command and result; never claim that a test, review, or workflow passed without verifying its result.
- Do not add new mandatory tools or change CI policy without a clear need and corresponding configuration/documentation updates.

## Automated code review

- Follow the repository's current `AI_POLICY.md`, `AGENTS.md`, and any applicable Copilot, CodeRabbit, or other automated-review instructions.
- Read every actionable automated review comment and evaluate it against the source, tests, API contract, security requirements, and repository conventions. Do not blindly apply suggestions that conflict with verified behavior or project architecture.
- Fix valid findings and add or update regression tests when a finding exposes a defect or behavior that needs protection.
- For findings that are invalid, duplicate, or not applicable, record a concise technical explanation in the review thread or pull request instead of silently ignoring them.
- After pushing substantive changes to a pull request, request or trigger a fresh automated review when the integration supports it. Check whether the review actually ran; do not claim that it was triggered or completed without evidence.
- Repeat the review-and-fix cycle for new actionable findings. Before merge, ensure actionable findings are fixed or explicitly resolved with a technically justified explanation, subject to required human review.
- Automated approval does not replace human review. A human reviewer must verify correctness, compatibility, security, and regression risk.

## Pull request expectations

- Explain the problem, root cause, and behavior changed.
- Summarize the tests and quality checks actually run, including exact failures and any checks not run.
- Call out public API, dependency, packaging, or Python compatibility implications.
- Disclose AI use and summarize AI-generated or AI-refactored portions, as required by `AI_POLICY.md`.
- Summarize material automated-review findings and their disposition; explain any unresolved or rejected actionable suggestion.
- Document non-obvious design decisions, especially those involving authentication, JWT validation, GraphQL responses, caching, price calculations, and asynchronous behavior.
