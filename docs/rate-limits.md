# Rate-limit errors

The request layer recognizes the observed GraphQL error message
`Too Many Requests` and HTTP status 429. It raises `RateLimitException`, a
subclass of `RequestException`, with these attributes:

- `operation_name`: the operation that received the response.
- `retry_after`: a nonnegative delay in seconds from a valid `Retry-After`
  response header, or `None` when no usable delay was supplied.

HTTP delay-seconds and all three HTTP-date formats are supported: IMF-fixdate,
obsolete RFC 850, and asctime. The asctime form has no timezone marker and is
interpreted as UTC, as required by HTTP. Other dates without a usable timezone
remain invalid. An expired HTTP-date produces zero seconds. No default API
quota or cooldown is inferred from a missing or malformed header.

`invoices()`, `login()`, and `month_summary()` propagate this exception.
Token renewal also propagates it without discarding authentication. Other
convenience methods retain their existing return-on-error contracts; this is
not a promise that every public method propagates all request exceptions.

The client does not sleep, automatically replay a request, or impose a global
cooldown. Callers can schedule a later update using `retry_after`, or use their
configured polling policy when it is `None`. Mutation retries require an
explicit decision by the caller.

The reported `path: ['invoices']` identifies the affected GraphQL field. It
does not establish whether the provider applies a field, account, IP, or global
rate limit.

## Home Assistant integration

The existing integration's `_fetch_invoices()` catches `RequestException` and
returns `None`, so adding the subclass alone does not change that behavior.
Handle `RateLimitException` before the generic no-data branch and propagate it
to the coordinator's update-failure handling, preserving the previous data
instead of publishing a successful update with `DATA_INVOICES = None`.

Respect the server-provided delay when scheduling a later refresh; otherwise
retain the configured polling policy. Do not treat throttling as invalid
credentials or renew tokens solely because the API is rate limited.
