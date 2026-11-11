# Repository skills

Apply these practices alongside [`AGENTS.md`](AGENTS.md) and [`AI_POLICY.md`](AI_POLICY.md). Update a practice when new evidence changes how to carry it out.

## Add read-only GraphQL operations with unverified response fields

- When a new GraphQL operation is supplied as a request but no live response
  exists, copy the operation name, selection set, and variable names exactly;
  use synthetic schema-shaped tests and clearly mark which semantics still
  require live verification. Do not invent prices, units, or provider rules.
- Preserve an explicitly null category and explicit empty `items: []`
  separately from a missing field, malformed object, or GraphQL error.
  Reject non-finite and non-numeric price data, including booleans, and
  keep unknown units and timestamp formatting unchanged.
- Use a separate parser for substantial new data models rather than
  increasing the complexity of a large unrelated parser. Export public
  classes, document the result contract, and test authentication, argument
  validation, negative prices, cancellation, and error propagation.
- Never include site references, account IDs, or complete provider
  responses in exception messages or logs. Mock API responses with
  fictional identifiers in regression tests.
- Redact provider errors **before** they reach shared GraphQL/HTTP logging,
  not only in a downstream response parser. Keep recognized auth,
  rate-limit and timeout classifications and the original error order.
  Test the real `_query()` route with mocked HTTP responses and `caplog`,
  including malformed error containers and private upstream reason text.
  A test mocking `_query()` cannot establish logging safety.
- For a privacy-safe GraphQL operation, audit every path **before**
  the response parser: unexpected error entries, malformed error containers,
  GraphQL validation, unhandled provider messages, HTTP reasons, client
  failures, and exception chaining. Redact log messages and raised error
  details, not just returned data; retain safe HTTP statuses and operation
  names for diagnostics.
- Preserve existing GraphQL error semantics when adding redaction:
  recognized authentication, retryable HTTP/GraphQL rate limits (including
  `Retry-After`), and timeouts must still take precedence in **response
  order**. Unknown errors must not mask recognized errors later in the
  same response. Use synthetic mixed-error regression cases to test both
  precedence and redaction, including errors in `extensions` and `path`.
- Before considering AI-review feedback complete, fetch review threads
  again from the latest PR HEAD: bots can automatically mark a thread
  resolved after a new push. An automatically resolved thread does not
  prove that the specific regression tests or final CI matrix passed.
- Changes to shared GraphQL routing can unintentionally change the
  **exact exception messages** of existing operations. After introducing
  operation-specific redaction, run the legacy Smart HVAC and other
  transport tests too; retain existing exception text for older API
  families and add new error messages only for the new operation.
- When an annotation-only test dependency triggers Ruff `TC002`, move
  the import under `if TYPE_CHECKING:` if postponed annotations are
  enabled. Treat separate Ruff-format, Ruff-lint, and pytest failures
  independently; use job logs to identify their actual causes.
- When sanitized live weighted-price evidence becomes available, record
  *observed structure* independently from the assumed schema. A March 2025
  response confirms 31 daily electricity entries, nullable gas/feed-in
  categories, UTC `from`/`till` strings, `KWH`, a negative daily market
  price, and a 23-hour local day during Europe's spring DST transition.
  Test the real calendar boundary with invented identifiers and prices;
  never replace observed provider values with client-calculated averages.
  Nonempty gas/feed-in and nullable prices remain unverified until observed.

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

## Verify concurrent authentication validation

- For local token validation, check both initial credential presence and the final
  return value under the same per-client renewal lock. A pre-lock check can become
  stale while another validator refreshes or clears the shared credentials.
- Reproduce renewal races with two tasks and `asyncio.Event` barriers. Mock the
  GraphQL request boundary (not the whole renewal method) to exercise the real
  state-clearing behavior after `RefreshTokenInvalidException`.
- Check both failed and successful overlapping renewals: neither waiting call
  may report credentials already cleared, and successful renewal should run
  only once. Verify request errors propagate and cancellation remains unhandled.
- Document the guarantee narrowly: local status is not proof of upstream token
  acceptance, and direct `renew_token()`/`logout()` calls bypass this lock.

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

## Audit schema-dependent Smart PV fields

- Distinguish checked-in query/model mappings from independently verified
  provider GraphQL type definitions. An existing query or synthetic fixture is
  not proof that all available provider fields have been discovered.
- Maintain a source-grounded field matrix with the GraphQL path, Python model
  type, nullable behavior, and the evidence boundary. Do not invent scalar
  types, `!` nullability or additional GraphQL field names from UI labels.
- Cover all query-selected fields in privacy-safe fixtures: at least one
  nonempty nested panel group and non-null summary `totalResult`, plus
  explicit null, missing/invalid, multiple-system and timezone-offset cases.
- Preserve the fail-closed inventory guarantees of #243. Distinguish
  a missing selected field from an explicit null; do not silently convert
  malformed non-null summary numbers or timestamps to `None`.
- If authorized schema introspection is unavailable, record the failure
  category and evidence boundary without exposing credentials or provider
  payloads. Avoid speculative query changes. For issue #244, acceptance
  covers independently verifiable fields only: an unavailable full schema
  is not by itself a blocker once mapping, tests, CI and human review are
  confirmed. Never claim provider-schema completeness.

### Lessons from historical GraphQL schema and third-party client research

- **Search issues and comments, not only source files.** An archived Home Assistant
  integration may have no `.graphql` or SDL file, while its issue history
  contains a genuine historical introspection result. For example,
  [bajansen/home-assistant-frank_energie #96](https://github.com/bajansen/home-assistant-frank_energie/issues/96)
  includes a 2023 `__schema` response listing 237 named types and 59 root
  query field names. That snapshot has no `smartPvSystems`,
  `smartPvSystemSummary` or Smart PV type definitions, and its fields-only
  selection does not establish GraphQL scalar types or nullability. Treat
  its date, selection depth and missing types as explicit evidence limits.
- **Inspect actual client GraphQL selections, not wish lists.** Compare third-party
  documentation against the precise queries checked into that repository.
  Proposed `capacity`, `maxPower`, `currentPower` or `todayGeneration`
  fields are not verified merely because a README or driver proposal lists
  them. Existing Smart PV queries in
  [RienduPre/homey-frank-energie](https://github.com/RienduPre/homey-frank-energie)
  and [hhi/org.hhi.onbalansmarkt-frankenergie](https://github.com/hhi/org.hhi.onbalansmarkt-frankenergie)
  did not establish any additional fields for the current typed inventory
  and summary models.
- **Separate related operations from fields in scope.** Historical or third-party
  `smartPvSystemConnectRequests` and `smartFeedInSessions` query examples
  are candidates for separately authorized, read-only verification. Neither
  proves current endpoint availability nor extends the existing
  `smart_pv_systems()`/`smart_pv_system_summary()` field contract.
- **Interpret introspection failures narrowly.** If authenticated `__typename`
  succeeds while `__schema` fails with `GRAPHQL_VALIDATION_ERROR`, the
  GraphQL connection works but the schema query was rejected; do not infer
  the provider's exact policy or that no further fields exist. Preserve only
  safe error categories, not provider error bodies, credentials or account
  identifiers. A historical export does not replace contemporary evidence
  for a newly selected GraphQL field.

### Lessons verified while reviewing PR #246

- **Update the snapshot source that pytest actually reads.** The active Syrupy file
  for the Smart PV tests is `tests/__snapshots__/test_smart_pv.ambr`, not
  `tests/snapshots/test_smart_pv.ambr`. After expanding a fixture, inspect the
  failed assertion and record the *actual* model representation, including
  `datetime.timezone.utc` versus `ZoneInfo("UTC")` in snapshot output.
  Updating an unused similarly named file does not fix the running test.
- **Validate the whole selected summary contract, not just successful parsing.**
  Test missing queried fields separately from explicit nullable values;
  malformed non-null totals, status types and timestamps must not silently
  become valid missing values. Retain direct-payload model parsing where
  supported, the existing enum fallback and UTC normalization for timezone
  offsets. Keep model exceptions privacy-safe and document intentional
  changes to the invalid-response contract.
- **Do not promote model observations to provider-schema facts.** A redacted
  `SmartPvSystem` and `SmartPvSystemSummary` observation verifies mapped
  values, including a nonempty panel group and non-null `total_result`;
  it does not enumerate all GraphQL fields or prove GraphQL scalar types,
  nullability, measurement units or accounting periods. The observed
  `onboarding_status=ACTIVE`, `operational_status=ON` and
  `steering_status=INACTIVE` are independent states, not evidence of
  electricity production or disconnection. Any *additional* field requires
  independent provider-origin evidence before implementation; the bounded
  issue #244 can close without proving that the provider schema is exhaustive.
- **Classify each CI failure against the current commit.** In PR #246,
  new fixture values initially failed two Syrupy snapshots, while separate
  Ruff format and `I001` import-order failures required their own minimal
  corrections (including a missing blank line between tests). Inspect the
  job log, fix the precise cause, and verify the entire 3.12/3.13/3.14
  matrix against the final head; all 30 CI jobs ultimately passed on
  `a873988`. A queued job or a passing superseded commit is insufficient.
- **Distinguish CI, automated review and actual PR state.** In PR #246,
  CodeQL and SonarCloud succeeded, but CodeRabbit was rate-limited and
  Sourcery's review was skipped; these are not equivalent to a completed
  independent human review. Read the live GitHub `draft`, `merged`,
  head/base and branch state rather than trusting a PR description that
  still says "Draft". Once a PR is merged and its branch deleted, start
  any new documentation change from current `main` in a separate PR.
