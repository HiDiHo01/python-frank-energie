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

- Inspect the relevant source, tests, and callers before changing behavior.
- Prefer the smallest complete change that fixes the underlying problem.
- Preserve existing public API behavior unless a breaking change is explicitly required and documented.
- Treat this repository as a standalone Python library. Do not add Home Assistant dependencies or use Home Assistant-only helpers in library code.
- Keep changes consistent with the existing module boundaries, naming, data models, and error-handling conventions.
- Do not add speculative fallbacks that hide malformed or unexpected API responses.
- Update tests and documentation when behavior or the public API changes.

## Python and implementation standards

- Respect the Python version declared in `pyproject.toml`; do not introduce syntax or APIs unsupported by the project's minimum Python version.
- Use modern Python syntax, precise type hints, and `snake_case` names.
- Add clear docstrings to modules, classes, methods, and public functions, following the surrounding code's conventions.
- Prefer built-in generic types such as `list[str]` and `dict[str, object]`; do not introduce legacy `typing.List` or `typing.Dict`.
- Use asynchronous I/O for network operations. Do not block the event loop with synchronous network or file I/O.
- Prefer the standard-library `asyncio.timeout()` for timeout management when the project's minimum Python version is Python 3.11 or later. Do not add or use `async-timeout` solely for timeout handling when `asyncio.timeout()` is available. Preserve compatibility with the declared minimum Python version and catch `TimeoutError` outside the timeout context manager.
- Apply explicit timeouts to network operations and handle cancellation correctly. Do not swallow `asyncio.CancelledError`.
- Use timezone-aware datetimes; avoid naive timestamps and deprecated datetime APIs.
- Use lazy `%` formatting in logging calls.
- Validate external input and API data at appropriate boundaries. Raise descriptive, domain-appropriate errors while preserving useful exception context.
- Keep imports used, avoid dead code, and maintain consistent exception handling.
- Do not add dependencies unless they are necessary and justified.

## Tests and quality checks

After changing code, run the relevant tests and checks in the Poetry environment. Start with:

```bash
poetry run pytest tests
poetry run pre-commit run --all-files
```

- Add regression tests for bug fixes, including relevant null, missing-field, malformed-response, and boundary cases.
- Use mocked API responses for tests; do not depend on live Frank Energie services or real credentials.
- Keep tests deterministic and isolated.
- If a check cannot be run, state that clearly in the pull request instead of claiming it passed.
- Investigate failures introduced by the change; do not bypass or weaken checks merely to obtain a passing result.

## Pull request expectations

- Explain the problem, the root cause, and the behavior changed.
- Summarize relevant tests and quality checks, including any that were not run.
- Call out public API or compatibility implications.
- Document non-obvious design decisions, especially those involving authentication, GraphQL responses, caching, price calculations, and asynchronous coordinator behavior.
