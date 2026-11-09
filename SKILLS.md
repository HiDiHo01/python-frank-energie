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

## Keep diagnostic logs safe

- For sensitive operations such as Smart HVAC, provider-controlled HTTP reason phrases and client exception messages are untrusted and may include EANs or device IDs. Log only safe operation names and numeric status codes; raise sanitized exceptions without displaying upstream exception chains. Preserve typed authentication and rate-limit behavior. Cover status codes and transport errors with synthetic secrets in both logs and exception text.
- Use fixed diagnostics and safe metadata such as operation names, durations, and counts. Signal degraded results without logging raw payloads or upstream error details.
- Trace nested model parsers as well as the top-level method. Use synthetic account, invitation, site, and HVAC values in log assertions so successful parsing and privacy are both verified.
