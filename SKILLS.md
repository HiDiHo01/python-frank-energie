# Repository skills

Apply these practices alongside [`AGENTS.md`](AGENTS.md) and [`AI_POLICY.md`](AI_POLICY.md). Update a practice when new evidence changes how to carry it out.

## Publish and maintain GitHub Pages documentation

### Verified architecture and ownership

- The public documentation site is
  [hidiho01.github.io/python-frank-energie](https://hidiho01.github.io/python-frank-energie/).
  The successful production deployment after PR
  [#285](https://github.com/HiDiHo01/python-frank-energie/pull/285)
  was confirmed by the [GitHub Pages workflow run](https://github.com/HiDiHo01/python-frank-energie/actions/runs/45185105267):
  both the **build** and **publish** jobs succeeded. Do not infer that later
  changes are live without checking their own runs and the URL.
- The website generator is Zensical. The authoring sources are `docs/**/*.md`
  and `docs/stylesheets/extra.css`, the navigation/configuration is
  `zensical.toml`, and the independently pinned builder is
  `requirements-docs.txt`. The generated `site/` tree is ignored by Git.
  Documentation dependencies must not be added to the SDK's runtime install.
- Keep the published site's disclaimer that this is an independent,
  community-maintained library. Do not publish account/site/device
  identifiers, access tokens, credentials, GraphQL payloads, or raw user logs.
  Examples must use safe placeholders or synthetic values.

### Document authoring and link hygiene

1. Edit the existing Markdown under `docs/` rather than making a second
   copy of the API reference. Use `docs/index.md` for the homepage and
   maintain `zensical.toml` navigation when pages are added, moved, or removed.
2. Use normal Markdown links between pages within `docs/`. For code,
   scripts, tests, or other files **outside** the documentation tree,
   link to their GitHub repository URLs: `../python_frank_energie/...`
   or `../tests/...` will not resolve in the rendered Pages site.
3. Treat `site_url = "https://hidiho01.github.io/python-frank-energie/"`
   and the trailing slash as significant. Check assets, links, and search
   under this project subpath, not only when serving at the web root.
4. Keep code snippets consistent with the declared Python minimum, the
   current SDK method signatures and async/session contracts. Never invent
   undocumented GraphQL fields, device semantics, or capabilities.
5. Do not include unrelated source files in the site artifact. Inspect
   generated HTML and assets before publication when changing templates,
   themes, or build configuration. Contributor instructions under `docs/`
   are repository files, not website pages: exclude `AGENTS.md` and
   `AI_POLICY.md` from the build, and use checkout-relative links between
   instruction files. Verify their absence from generated pages, search
   and sitemap, not just navigation. Zensical's `exclude_docs` uses gitignore
   patterns: unanchored basenames match at any depth; a leading slash only
   matches the documentation root. The Pages build checks the actual output
   and an isolated fixture with root and nested instruction files plus a
   public control page before any upload.

### Development and validation

Run the documentation checks locally when the builder is available:

```bash
python -m pip install -r requirements-docs.txt
zensical build --clean
test -s site/index.html
test -s site/getting-started/index.html
test -s site/ARCHITECTURE/index.html
test -s site/privacy-policy/index.html
zensical serve
```

- The last command starts a **local preview**. Verify navigation, search,
  styles, light/dark display and mobile layout in a browser. On Windows,
  replace the shell `test -s` assertions with suitable file existence
  and nonempty checks; the GitHub Actions runner executes them on Linux.
- Re-run applicable documentation and repository quality checks, including
  `blacken-docs` for fenced Python examples and existing pre-commit checks.
  CI can run all hooks across Python 3.12/3.13/3.14 even for documentation-only
  changes. A formatter failure in an **unchanged** file may be inherited:
  compare the failed file with `main` before attributing the error to
  your patch; do not hide, skip or falsely dismiss a genuine regression.
- Record the **actual** command, build output, commit SHA and CI run
  conclusion. If the local generator cannot be installed, report that
  limitation, then verify a successful GitHub Actions build. Do not equate
  an unrun local check with success.

### Safe GitHub Actions publishing

- The documentation workflow is `.github/workflows/docs.yml`. It builds
  on relevant pull-request changes; pull requests must not upload or deploy
  the Pages artifact. The deployment is permitted only from
  `refs/heads/main`, including `workflow_dispatch` runs. A manual
  dispatch on another branch may build, but must never publish.
- The build job needs only `contents: read`. The deployment job, protected
  by `github-pages` environment, receives `pages: write` and
  `id-token: write`. Prefer SHA-pinned GitHub Actions rather than mutable
  version tags. Recheck action versions and permissions before updating.
- In **Settings → Pages → Build and deployment**, the publishing source must
  be **GitHub Actions**. Repository metadata such as `has_pages: true` or
  `homepage` alone does not establish that a new deployment succeeded.
  PR jobs correctly skip deployment; only a successful production deployment
  job confirms publication.
- Avoid deploying from an unreviewed or feature branch through manual
  triggers. Keep a separate build and deploy job, with a precise branch
  condition on any upload/deploy step. Never expose secret values via
  documentation builds or user-supplied content.

### Review, synchronization, and release verification

1. Read applicable `AGENTS.md` and `AI_POLICY.md`, inspect the current
   `main` branch, Pages configuration, and the prior PR/review status.
2. Create a focused branch/PR. AI-assisted changes require human review and
   an AI-assistance note in the PR description. Build in CI, but do not
   publish or merge merely because the build is green.
3. If `main` advances during review (as happened when SDK PR #284 was
   merged while website PR #285 was open), reconcile the branch with
   `main`, preserving its other changes. Inspect the resulting diff to
   ensure only intended documentation files remain, and rerun all checks
   on the **updated commit**. Do not force-push without authorization.
4. Confirm each required CI job and unresolved review thread on the latest
   head; historical passing runs and queued checks are not sufficient.
   Record any remaining review, permission or Pages configuration blockers.
5. After an approved merge, inspect the `main`-triggered **GitHub Pages**
   workflow: the documentation build *and* deployment jobs must succeed.
   Open the canonical URL to check HTTP availability, expected content,
   navigation and CSS/assets. Report GitHub's deployment success and
   direct public-site verification **separately** if one cannot be checked.
6. Use the post-deployment HTTP verification job to check every public
   navigation page on the canonical project URL. Keep its route list in sync
   with `zensical.toml`; preserve case and trailing slashes. Require HTTP 200
   without redirects. Use a shared five-minute propagation retry window,
   retry only failed routes at up to 20-second intervals, and cap each
   request at 15 seconds. The final sweep may finish after the deadline;
   report every persistent failure. A failed verification does not undo a
   deployment. Run it only after successful production publication, without
   deployment permissions.

## Diagnose unknown Smart Battery status values without disclosing identifiers

- Inspect `smartBatterySummary.lastKnownStatus` in `SmartBatterySummary.from_dict()`
  **before** enum conversion: missing, null, empty, explicit `UNKNOWN`
  and new values would otherwise collapse to the same fallback.
- Keep the public summary dataclass and the `UNKNOWN` fallback unchanged.
  Emit one diagnostic per sanitized status token, only allowing status-shaped
  alphabetic identifiers; redact arbitrary strings and unexpected value types.
  Never log battery IDs, account details or entire GraphQL/model payloads.
- Treat API timeouts and unavailable details separately from a parsed
  `SmartBatteryStatus.UNKNOWN`: the SDK's `smart_battery_details()` method
  returns `None` for most request errors, before parsing the summary.
  Include both HTTP client timeouts and the backend's GraphQL timeout
  exception in the timeout category. Record bounded, identifier-free failure
  reasons once per reason per process.
  Never log upstream error objects, payloads or battery IDs as part of these
  diagnostics. A successfully parsed enum status is not a transport failure.
- Test recognized statuses, unknown status-like tokens, explicit `UNKNOWN`,
  missing/null/empty fields, malformed values, timeouts, HTTP/network errors,
  malformed/missing summaries, and de-duplication with `caplog`.
  A fresh summary timestamp does not prove the provider supplied a usable status.
- Apply the same rule to other optional status fields on the summary
  (`activityStatus`, `status`, `gridCongestionStatus`): log an unknown value
  verbatim only when every word of it is in the battery-status vocabulary, never
  because it merely looks like an identifier (a UUID or account number is
  identifier-shaped). Report anything else as a redacted category, once per enum.
  Test an identifier-shaped value explicitly. Widening the vocabulary also
  widens what `lastKnownStatus` diagnostics log, so add words deliberately.

## Preserve nullable provider billing data without inventing zeros

- Inspect **raw JSON before model parsing** when provider zero and missing
  values differ. Observed November 2026 MonthInsights responses have
  `expectedCostsGas: 0` with `gasDifference: null`, sometimes
  `expectedCostsFeedIn: 0` with `feedInDifference: null`, while other
  accounts have real negative feed-in usage and costs. Preserve independent
  optional blocks and genuine numeric zeros; do not turn null blocks into
  zero-filled objects.
- Reject malformed non-null numbers, flags, units, and nested objects using
  sanitized field names, without including private IDs or financial values
  in exceptions or DEBUG logging. Retain null/missing as unavailable and
  validate the Home Assistant consumer against newly optional model types.
- A real future-month MonthInsights request returned `monthInsights: null`
  with a **single missing-meter-readings error** at path
  `["monthInsights"]`. Classify this exact shape before parsing and return
  `None` without exposing the opaque identifier. Reject other/mixed
  GraphQL errors. Preserve rate-limit retry information and cancellation.
- Keep requested `YYYY-MM` month separate from the reading date and the
  source ID suffix. Year-only API support has not been established.
  Exercise the shared HTTP transport with synthetic account identifiers,
  including malformed and ambiguous missing-data responses.
- Reject malformed non-null MonthInsights records with a missing/blank opaque
  `_id`; do not treat an empty object as usable billing data. Include timezone
  conversion in guarded date validation, test both Python datetime boundaries,
  and lock dataclass positional field order with distinct argument values.

- Reuse stable constants for sanitized missing-reading messages and UTC
  suffixes. When Sonar suggests `\d` for a strict year-month pattern, use
  `re.ASCII` so Unicode numerals remain invalid. Existing GraphQL-style
  public model attributes are compatibility constraints: do not rename them
  solely to satisfy generic naming rules; document the exception for review.
- Offer `snake_case` through explicit typed, writable properties that forward
  to existing camelCase dataclass fields; never duplicate state or rename
  positional/keyword constructor arguments. Test read/write in both directions,
  nullable values, `dataclasses.fields()`, `dataclasses.asdict()`,
  `dataclasses.replace()`, and the original constructor signatures. The
  original field names stay in serialized dataclass output.

## Expose optional periods from opaque model IDs without leaking identifiers

- Preserve existing opaque ID fields, dataclass constructors, parser return
  types, and snapshots. Add a read-only computed property rather than a new
  serialized or positional dataclass field.
- Accept only the observed `|YYYY-MM` suffix for `MonthSummary` and
  `MonthInsights`, using exact full-string matches, ASCII digits, a valid
  calendar year and month, and a single nonempty prefix.
  Validate the prefix for each model. `MonthInsights` permits spaces in
  printable prefix text. `MonthSummary` rejects whitespace in its prefix.
  Return `None` for year-only (`|YYYY`), missing, legacy, ambiguous,
  malformed or unsupported identifiers rather than inventing a month.
- Do not claim a billing period is complete from a source ID,
  the last meter-reading date or day completeness.
- Never log or newly expose the private prefix of an upstream ID; inspect
  existing model debug logging while touching ID parsing. Validate both
  standard and legacy parser methods, sanitization, and year rollovers
  using fictional identifiers.

## Promote historical read-only GraphQL examples safely

- Treat commented GraphQL requests as *unverified discovery material*, not an active
  provider contract. Preserve their exact named operation, root field, variables,
  and fragment selections while introducing one independently reviewable public
  method per query.
- Require authentication and use the established GraphQL transport rather than
  adding a second HTTP/session path. Do not print full response bodies, even in
  DEBUG logs: reward, account, and subscription fields may contain personal data.
- At the parser boundary, distinguish an explicitly returned `null` from a
  missing root, malformed response, or GraphQL error. Preserve successful empty
  collections only when the provider explicitly returned `[]`; never infer them
  from an error.
- For nested `userSites[].address.addressFormatted`, validate the
  actual `list[str]` shape and each nonempty line before mapping it to a
  top-level alias or structured `Address`. Do not coerce malformed elements
  to strings or log complete site, address, or identifier payloads. Keep
  first-site legacy summaries distinct from per-site objects and test both.
  Emit malformed-address warnings while parsing each delivery site so the
  first-site summary cannot duplicate the warning. Test the exact message
  and count with mixed valid, missing, null, and malformed addresses.
- Use synthetic regression fixtures, especially for nullable nested fields.
  Two 2026-11-11 `UserSmartCharging` responses confirmed
  `provider: "ENODE"` and both `isActivated: false` with null
  `userCreatedAt`/`userId`, and `isActivated: true` with a populated
  UTC timestamp string and opaque `userId`; `subscription` was null
  in both. Preserve those distinct states and use synthetic IDs and dates.
  An `AppVersion` response confirmed `ios: null` and
  `android: null`, and a `UserRewardsData` response confirmed
  `rewardPayoutPreference: "DISCOUNT"`, a single active connection,
  and two explicit empty reward lists. A later response showed
  one populated `acceptedRewards` record with nullable
  `awardedTreesAmount`, timestamp strings, flags, nested `InviteLink`,
  and an explicit empty `AdditionalBonuses` list. Use synthetic values
  for `me.id`, `UserSettings.id`, `acceptedRewards.id`,
  `InviteLink.id`, `InviteLink.fromName`, and all dates in tests;
  do not store actual account or referrer details. A `TreeCertificates` response
  confirmed an explicit successful empty list (`treeCertificates: []`),
  but not the shape of nonempty certificate records. An observed
  `AppNotice` response confirmed `active: true`, a non-empty
  `message`, and `title: ""`. Preserve the empty title as a string,
  not `None`, and use an invented notice message in regression fixtures
  rather than storing an actual provider announcement.
- Validate both operation name/selection and result handling; preserve request
  errors, `RateLimitException.retry_after`, and cancellation without retries.
  Check non-null nested selections and list-valued roots at their parser
  boundaries; explicit null must remain distinct from malformed records.
  Ensure the shared HTTP/GraphQL path rejects malformed envelopes *before*
  accessing error fields and never logs returned private account data.
  Exercise that path with mocked HTTP responses, not only a mocked `_query`.
  Keep unverified live support clearly marked in the PR and documentation.

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
- When a public API call may **renew an expired token before its own GraphQL
  request**, include the nested `RenewToken` operation in the privacy
  review. Sanitize transport, status, and unknown GraphQL errors at the
  renewal boundary, without changing recognized authentication,
  refresh-token-invalid, or rate-limit classifications.
- Validate the full response-decoding boundary: `resp.json()` can raise
  both `aiohttp.ContentTypeError` for an unexpected media type on HTTP 200
  and `json.JSONDecodeError` for invalid JSON despite an expected media
  type. For sensitive operations, map both to the same sanitized
  `RequestException`; keep other operations' legacy HTTP handling.
  Explicitly malformed `errors` values must not produce different
  exceptions based on truthiness. Test all cases through mocked
  HTTP responses with `caplog` and synthetic secret markers.
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
   For SonarCloud findings, identify the SonarCloud Code Analysis check run for the exact PR head SHA and read its GitHub Checks API annotations (`/repos/{owner}/{repo}/check-runs/{check_run_id}/annotations`). Record the rule message, file, and line, then verify each against the current source. A passed quality gate can still include new issues. If annotations cannot be retrieved, follow the authorized CI-runner fallback above.
   In tests that verify several files remain unchanged, save a separate baseline for each file and assert the current value first (`assert path.read_bytes() == baseline`). This matches the surrounding test style and makes a failure identify which file changed.
3. Reproduce confirmed defects with sanitized data where possible. Verify the smallest fix with relevant checks, then link the commit and evidence when replying. Explain the disposition of invalid, duplicate, or obsolete findings before resolving the thread.
<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:538bde2024fdc8f43bb28e42bf88a07a3ffa133e2785c70698be265e0ca5d4bf -->

4. After the final push and again after automated review, check the current PR head. Whenever the head changes, revalidate all findings previously marked obsolete against the new head before reporting feedback complete. Confirm the actual thread count, workflow jobs, and quality results for that commit. Identify whether review completed, was skipped, or was rate limited. If supported and authorized, use a documented manual review trigger.

<!-- /coderabbit-ai-generated:v1 -->

## Synchronize the Home Assistant integration after a published release

- Keep the cross-repository update in `.github/workflows/sync-home-assistant-on-release.yml`, triggered only by `release: published` for stable releases. Verify the tag against the tagged package metadata and wait until PyPI exposes a usable non-yanked wheel before proposing a downstream change.
- Scope the GitHub App installation to `HiDiHo01/home-assistant-frank_energie` with Contents and Pull Requests write permissions. In the source repository, `HiDiHo01/python-frank-energie`, configure `HA_DEPENDENCY_BOT_APP_ID` as an Actions variable and `HA_DEPENDENCY_BOT_PRIVATE_KEY` as an Actions secret. Keep the source `GITHUB_TOKEN` read-only and run dependency preparation without the App token.
- Use `scripts/sync_home_assistant_dependency.py` for validated, monotonic updates to `manifest.json` and the Poetry dependency. A compatible existing Poetry minimum (`>=<version>`) can be below the manifest's exact pin; normalize it to the published exact pin even if the lock is current. Reject newer minimums, invalid versions, and unsupported or duplicate declarations. Use the downstream project's Poetry version to refresh the lockfile with `poetry lock` and verify the exact published library version. Keep compatible locked resolutions.
- Queue release updates together and prepare every retry from downstream `main`. Reuse matching release commits and keep the history of a refreshed automation branch so the push can fast-forward. Close superseded pull requests only when they originate from the same GitHub App and downstream repository.
- Open a release-specific, idempotent downstream pull request and leave merging to a human reviewer. Preserve the integration's release `version` and require the downstream compatibility checks before merging.
- The Home Assistant coordinator and Smart HVAC `api.me(site_reference)` callers must be compatible with the new library before merging the dependency PR. Missing required API arguments (for example `smart_hvac_status(site_reference)`) can otherwise prevent config-entry setup.

## Refactor without changing GraphQL error contracts

- **PR #256 SonarQube Cloud maintainability findings:** replace repeated
  provider and error-message literals with descriptive module constants;
  preserve the *exact* public exception text and distinguish prefix
  matching (such as a missing connection) from full error-code equality.
  Extract operation-specific error classification into a private static
  helper when it lowers `python:S3776` Cognitive Complexity, but keep
  the shared GraphQL error loop and response-order precedence unchanged.
  Cover known and unknown provider errors, privacy-safe exception messages,
  and the behavior of other operations in regression tests. Verify that
  both the Python CI matrix and the updated Sonar issue count agree before
  declaring the findings closed.
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

## Retire an obsolete model parser without losing regression coverage

- Verify repository-wide and downstream usage before removing a public parser.
  In the 2026-11 MonthSummary cleanup, `old_from_dict()` was referenced only
  by its SDK definition, tests and architecture documentation; no calls were
  found in the Home Assistant integration. External consumers may still
  depend on it, so flag the removal as an intentional breaking API change.
- Migrate the parser-specific tests to `MonthSummary.from_dict()` while
  retaining their original payload and boundary assertions. Add a regression
  check that the removed method is absent so it cannot be reintroduced
  accidentally.
- Preserve the supported parser's existing error precedence, absent-response
  semantics, cost calculations, and two-argument daily-average utility.
  The removed parser returned `None` for an empty mapping and invented
  defaults for several populated-summary fields; `from_dict()` rejects an
  invalid envelope or incomplete populated summary. Document these behavior
  differences and the consumer's required error handling, not just the method
  rename. Validate the latest PR head across all configured Python and
  pre-commit checks before merging.

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

- **PR #256 Ruff-only CI lesson:** Six failed jobs across Python 3.12,
  3.13, and 3.14 were **lint/format failures, not pytest failures**; the
  pytest and mypy jobs already passed. Read the job name and the failing
  hook's diagnostic before changing tests or production behavior.
  Ruff `I001` was caused by the stdlib `TYPE_CHECKING` import being placed
  before `datetime` in `tests/test_weighted_average_prices.py`, despite
  correctly moving `aresponses.ResponsesMockServer` into a
  `TYPE_CHECKING` block for `TC002`. Keep both rules satisfied: type-only
  imports in the guard, and all import statements ordered by Ruff/isort.
- **PR #256 formatter lesson:** A multi-line `or`/generator expression in
  `frank_energie.py` was semantically correct but needed the parentheses
  and indentation produced by Ruff format. Do not weaken tests or rewrite
  business logic to repair formatting. Run `poetry run ruff format --check .`
  and `poetry run ruff check .` independently before pushing. After the
  minimal formatting commits `dd52ac5` and `7b477a9`, GitHub Actions
  run `43093678526` on HEAD `7b477a9` reported **74 successful, 2
  skipped, 1 neutral, 0 failed** checks; pytest, mypy, Ruff lint and Ruff
  format passed on all three supported Python versions. These results
  apply to that commit only, not automatically to later documentation commits.
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
- GraphQL introspection is blocked for Frank Energie: do not attempt
  `__schema` or `__type` queries, retries, discovery probes, or fallback
  introspection. Instead, use dated provider documentation and verified,
  authorized application/API requests with sanitized responses. Record
  unknown argument types, fields and semantics explicitly; never infer them
  from a generic `Graphql validation error` or a historical schema snapshot.
  Avoid speculative query changes. For issue #244, acceptance covers
  independently verifiable fields only: the unavailable full schema is not
  itself a blocker once mapping, tests, CI and human review are confirmed.
  Never claim provider-schema completeness.

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

## Validate Smart Battery provider status evidence

- Keep the provider and observation scope explicit. As of 2026-11-24,
  HYXI author observations include `CHARGING`, `DISCHARGING`, `STANDBY`,
  `CONNECTED` and `NOT_ENROLLED`; two Sessy devices independently returned
  `CHARGING`, `CONNECTED` and `ENROLLED` with a null `lastKnownStatus`.
- Preserve `lastKnownStatus`, `activityStatus`, `status` and
  `gridCongestionStatus` independently. `ENROLLED` is observed;
  `ACTIVE`, Anker acceptance and offline/unreachable semantics remain
  unverified.
- Add enum values only from sanitised, authorised observations. Never use
  GraphQL introspection or speculative fallback requests. A mocked GraphQL
  field-validation error can characterize the existing exception path, but
  cannot establish that a provider rejects the field.

- The SDK must not set a process-wide asyncio event-loop policy based on
  `sys.platform`; event-loop policy belongs to the consuming application.
  Keep the regression test asserting that importing the SDK under a simulated
  Windows platform does not call `asyncio.set_event_loop_policy()`.
- For a GraphQL field-validation error, test the existing exception contract
  with a mocked response and assert one request only. This characterizes the
  current behavior; it is not evidence that a provider actually rejects the
  field and must not introduce a fallback or retry.
