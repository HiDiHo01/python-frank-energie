# Repository skills

Apply these practices alongside [`AGENTS.md`](AGENTS.md) and [`AI_POLICY.md`](AI_POLICY.md). Update a practice when new evidence changes how to carry it out.

## Address pull request feedback

1. Record the current PR head and base. Fetch all pages of inline review threads and check their resolved state, including outdated threads. Before assessing or resolving each unresolved thread, fetch every page of its comments, including replies on outdated threads. Read actionable findings in the conversation and review summaries.
2. Compare each finding with the current diff, tests, and API evidence. Open static analysis annotations even when the quality gate passes. If a finding points to older base code, check whether the current base already contains the fix before changing the PR.
   When annotation access is blocked, obtain public nonsecurity SonarCloud issue metadata through an authorized CI runner without credentials. Do not expose security-sensitive findings in public logs; remove the temporary inspection workflow when finished and verify the current PR head.
3. Reproduce confirmed defects with sanitized data where possible. Verify the smallest fix with relevant checks, then link the commit and evidence when replying. Explain the disposition of invalid, duplicate, or obsolete findings before resolving the thread.
<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:538bde2024fdc8f43bb28e42bf88a07a3ffa133e2785c70698be265e0ca5d4bf -->

4. After the final push and again after automated review, check the current PR head. Whenever the head changes, revalidate all findings previously marked obsolete against the new head before reporting feedback complete. Confirm the actual thread count, workflow jobs, and quality results for that commit. Identify whether review completed, was skipped, or was rate limited. If supported and authorized, use a documented manual review trigger.

<!-- /coderabbit-ai-generated:v1 -->

## Synchronize the Home Assistant integration after a published release

- Keep the cross-repository update in `.github/workflows/sync-home-assistant-on-release.yml`, triggered only by `release: published` for stable releases. Verify the tag against the tagged package metadata and wait until PyPI exposes a usable non-yanked wheel before proposing a downstream change.
- Scope the GitHub App installation to `HiDiHo01/home-assistant-frank_energie` with Contents and Pull Requests write permissions. In the source repository, `HiDiHo01/python-frank-energie`, configure `HA_DEPENDENCY_BOT_APP_ID` as an Actions variable and `HA_DEPENDENCY_BOT_PRIVATE_KEY` as an Actions secret. Keep the source `GITHUB_TOKEN` read-only and run dependency preparation without the App token.
- Use `scripts/sync_home_assistant_dependency.py` for validated, monotonic updates to `manifest.json` and the Poetry dependency. Use the downstream project's Poetry version to refresh the lockfile with `poetry lock` and verify the exact published library version. Keep compatible locked resolutions.
- Queue release updates together and prepare every retry from downstream `main`. Reuse matching release commits and keep the history of a refreshed automation branch so the push can fast-forward. Close superseded pull requests only when they originate from the same GitHub App and downstream repository.
- Open a release-specific, idempotent downstream pull request and leave merging to a human reviewer. Preserve the integration's release `version` and require the downstream compatibility checks before merging.
- The Home Assistant coordinator and Smart HVAC `api.me(site_reference)` callers must be compatible with the new library before merging the dependency PR. Missing required API arguments (for example `smart_hvac_status(site_reference)`) can otherwise prevent config-entry setup.

## Refactor without changing GraphQL error contracts

- When SonarCloud flags request orchestration or error classification for cognitive complexity, extract small helpers at existing boundaries (such as authentication/header preparation or error-container validation) rather than altering exception order, redaction, or partial-response semantics.
- In async request methods, delegate `ClientError` and `KeyError` mapping to small `@staticmethod` helpers returning `Never` when reducing `python:S3776` complexity. Preserve sanitized `raise ... from None` for sensitive operations and original `raise ... from error` for legacy operations; cover both paths with deterministic tests.
- In `pytest.raises` blocks, calculate auxiliary values (for example, timestamps) beforehand so the context contains only the single operation expected to raise. Recheck the new PR head after a fresh SonarCloud analysis; a concurrent audit workflow may temporarily report findings from the previous scan.

## Handle partial GraphQL responses

- Use the exact GraphQL response path to identify a failed optional field. Verify that the operation supports partial recovery and that its required data is usable. The site-specific `me()` implementation proposed in PR #226 illustrates these checks in its [regression tests](https://github.com/HiDiHo01/python-frank-energie/blob/b3b0be752c0cff33c32c7e8511ca189e713cabbc/tests/test_me_partial_errors.py).
- Classify errors in their original order before using partial data. Preserve typed authentication, rate-limit, timeout, and validation failures. Keep malformed, unscoped, mixed, and required-field errors on the operation's normal error path.
- Preserve the successful sibling data and clear the failed optional subtree. Keep `None`, `False`, and a successful empty collection distinct. Validate optional boolean fields without coercing strings or numbers.
- Verify schema support before adding fields or compatibility retries. Test the actual query selection and arguments independently of mocked response data. Exercise the public method through mocked HTTP responses when testing request error handling.
- Keep HTTP exception mapping, GraphQL response handling, and model parsing focused. Check exception types, error order, and `Retry-After` handling after moving code between these layers.

## Validate optional device API boundaries

- For each new GraphQL operation, reject non-object decoded responses **before** generic error handling; a nonempty JSON list must raise the library's domain exception rather than `AttributeError`.
- If an `errors` key is present, validate the container even when it is empty or falsey. Require a list with valid entries and preserve the existing ordered authentication, rate-limit, and timeout classification. Do not convert malformed errors into successful empty inventories.
- Require every field selected by a device inventory or connect-request query to be present in each returned record; permit explicit nulls for nullable fields. Reject incomplete records atomically rather than fabricating incomplete objects. Test each omitted field separately from explicit null values.
- Translate numeric overflows (integer-to-float and offset-aware timestamp normalization) to the established `RequestException`. Exercise extreme but synthetic values in regression tests.
- Escape literal `|` characters in Markdown table cells documenting nullable union return types so the rendered API table retains the correct columns.

## Verify Smart PV empty-inventory versus feature-disabled outcomes

- A live, sanitized `SmartPvSystems` response for an account without Smart Feed-In contained `{"data": null, "errors": [{"message": "user-error:smart-feed-in-not-enabled", "path": ["smartPvSystems"]}]}`. This is a **feature-disabled error**, not a successful, verified `smartPvSystems: []` inventory.
- Preserve a distinct `SmartFeedInNotEnabledException(RequestException)` for that exact single-error, null-data response at the public `smart_pv_systems()` boundary. Keep `user_smart_feed_in()` and other operations unchanged; reject mixed and differently scoped errors.
- Require complete queried PV-system records, unique system IDs, valid nested panel groups, and valid unique panel-group IDs before exposing an inventory. A missing, malformed or partially invalid response must fail closed. An explicit successful `smartPvSystems: []` is the only authoritative empty inventory.
- Regression-test both the HTTP GraphQL request path and the actual model parser with synthetic fixtures. A mocked `SmartPvSystems(systems=[])` does not prove the provider response was valid. Home Assistant Repairs must not count feature-disabled outcomes as confirmed absence; see [issue #243](https://github.com/HiDiHo01/python-frank-energie/issues/243) and [integration issue #455](https://github.com/HiDiHo01/home-assistant-frank_energie/issues/455).

### Preserve existing Smart PV enum semantics during validation

- Inspect `domain.py` before assuming that an unknown provider status should raise. `SmartPvSteeringStatus` inherits `_FallbackStrEnum`, whose `_missing_()` maps new/unrecognised values to `UNKNOWN`. In [PR #245](https://github.com/HiDiHo01/python-frank-energie/pull/245), a new regression test initially expected a `RequestException` for an unknown steering status; the real model correctly returned `UNKNOWN`. Correct the **test expectation** to match this compatibility contract, rather than making the global enum stricter as a side effect of an inventory fix.
- Distinguish **structural integrity** (complete response, properly typed collections, all selected fields present, valid nonblank/unique system and panel-group IDs) from **forward-compatible status values**. Fail closed on incomplete or malformed inventory structures, but preserve documented `UNKNOWN` enum fallbacks and valid nullable fields. Trace `SmartPvSystem.from_dict()` and nested parsers to find any silent filtering or coercion before choosing the validation boundary.
- Keep the fail-closed validator simple: extract stable-ID validation and nested panel-group validation into small dedicated helpers. Check SonarCloud `python:S3776` and the repository's cognitive-complexity limit (15) without changing the public API or broadening GraphQL error handling.
- **Review lesson from PR #245:** `_as_int` and `_safe_float` may return `None` for malformed **non-null** panel values; `int(_safe_float(...))` may truncate fractional counts. Validate raw non-null numerics and optional timestamps before constructing PV panel groups, preserving genuine nulls and supported numeric strings. Check required string metadata (including `connectionEAN`) before `str()` can turn `None` into `"None"`, and reject malformed non-null `deletedAt` while permitting null. Test these error cases with fictitious values and capture DEBUG logs in privacy assertions.

## Keep diagnostic logs safe

- For sensitive operations such as Smart HVAC, provider-controlled HTTP reason phrases and client exception messages are untrusted and may include EANs or device IDs. Log only safe operation names and numeric status codes; raise sanitized exceptions without displaying upstream exception chains. Preserve typed authentication and rate-limit behavior. Cover status codes and transport errors with synthetic secrets in both logs and exception text.
- Use fixed diagnostics and safe metadata such as operation names, durations, and counts. Signal degraded results without logging raw payloads or upstream error details.
- Trace nested model parsers as well as the top-level method. Use synthetic account, invitation, site, and HVAC values in log assertions so successful parsing and privacy are both verified.

## Preserve typed provider errors across public API wrappers

- Distinguish confirmed resource absence from throttling. In `smart_battery_sessions()`, only `SmartBatteryNotFoundException` may produce a not-found `None`; `RateLimitException` must propagate unchanged so downstream consumers retain `operation_name` and `retry_after`.
- The async GraphQL request also performs implicit token renewal when authentication has expired. Test both session-query throttling (GraphQL and HTTP 429) and renewal throttling (with preserved authentication and no subsequent sessions request) at the public method boundary.
- Assert that cancellation is propagated and successful session parsing still uses the original model parser. Keep device identifiers, upstream response bodies, and provider exception details out of session request logs.
- After a published release, verify downstream integrations against the released dependency rather than assuming that upstream `main` matches their pinned runtime version.
- For non-throttling session-query failures that still use the legacy `None` fallback, log a fixed category (`timeout`, `network`, `authentication`, or `other`) rather than provider-controlled exception messages; cover each with synthetic sensitive values.

## Introduce compatible public API aliases

- Introduce snake_case public methods as small typed async wrappers around existing methods before renaming or moving legacy implementations. Preserve arguments, return objects, authentication checks, and raised exceptions; do not create a second GraphQL code path.
- Use deterministic regression tests to check explicit and default arguments, result identity, and exception propagation. Keep existing callers working until any separately reviewed deprecation is justified and documented.
- Before inserting an alias inside a class, check class-local name resolution for return annotations. In PR #240, placing `user_sites() -> UserSites` **after** `def UserSites(...)` made mypy resolve `UserSites` to the method (`[valid-type]`); moving the alias **before** the legacy method resolved the conflict without behavior changes. For a larger refactor, prefer a distinct imported model alias to avoid order-dependent annotations. Verify with `poetry run mypy python_frank_energie` before pushing.
- If callers inspect annotations at runtime, verify the evaluated annotations on the supported Python versions as well. Python 3.14 resolves both site methods' return annotations to the class-local `UserSites` method when evaluated, even though mypy passes and the methods return the model.
- When a regression test nests `patch.object(...)` and `pytest.raises(...)`, Ruff `SIM117` expects one parenthesized `with` with both managers. Keep setup outside `pytest.raises` and only the call expected to raise inside the block.

## Prepare an incremental refactoring

1. Start from current `main`. Trace each affected operation from its public entry point through the state it reads or writes, the request boundary, and result parsing. Compare the trace with the [architecture reference](docs/ARCHITECTURE.md) and record any gaps as open questions.
2. Inspect package exports, direct module imports, and known callers for dependence on class identity, field aliases, defaults, and fallbacks. Record any deliberate compatibility change for separate review before moving code.
3. Run the same characterization checks against the base and the proposed change using sanitized responses. Assert observable results, the original exception or exception type as appropriate, and resulting client state. Exercise cancellation, concurrent renewal, and both injected and internally created sessions where the change touches those paths.
4. Move one responsibility per PR. Verify the public entry points and known downstream callers, then update the architecture reference with the behavior established by the tests.

## Diagnose and verify PR CI failures

- **PR #245 regression lesson:** a first CI run failed Ruff formatting because its hook reformatted one Python file; commit the exact formatter change and run formatting checks on the new head. The first pytest run also failed a newly written unknown-steering-status assertion; inspect the existing `_FallbackStrEnum` behavior before changing application code. After both fixes, rerun the full applicable Python 3.12/3.13/3.14 CI matrix and verify results on the **last commit**, including checks started by any later refactoring.
- Keep formatting failures, behavioral test failures, and pending automated reviews separate in the status report. A green test suite on a superseded commit is not evidence for the current head; skipped/unavailable reviews and SonarCloud coverage measurements do not equal completed independent human review.
- Identify the current PR head SHA and the corresponding workflow run, then inspect **failed job logs** for the exact source location and diagnostic rather than assuming every red job is a failed unit test. PR #240 first failed mypy on Python 3.12/3.13 (`[valid-type]`), then Ruff on Python 3.13 (`SIM117`); both fixes were local to their root causes.
- Preserve passing behavior and tests; make the minimal corrective commit, describe the reason in the PR, and inspect the **new** run on the updated SHA across every required Python version and job. Never report CI success based on an older commit, a queued run, or a partial job count.
- Relevant checks include `poetry run ruff format --check .`, `poetry run ruff check .`, `poetry run mypy python_frank_energie` and `poetry run pytest tests`. Record which commands were actually executed locally and which results were observed only in GitHub Actions.
