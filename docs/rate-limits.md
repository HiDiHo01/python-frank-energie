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
remain invalid. RFC 850 two-digit years use a rolling 50-year future boundary;
a timestamp beyond that boundary represents the matching past year. Invalid
calendar dates remain unusable. An expired HTTP-date produces zero seconds. No default API
quota or cooldown is inferred from a missing or malformed header.

`RateLimitException` propagates from every method that does not catch request
errors itself: `invoices()`, `login()`, `month_summary()`, `renew_token()`,
`validate_authentication()`, `user()`, `me()`, `UserSites()`, `user_country()`,
`prices()`, `user_prices()`, `country_prices()`, `meter_readings()`,
`smart_hvac_status()`, `smart_pv_systems()`, `smart_pv_system_summary()` and
`user_smart_feed_in()`. Token renewal keeps authentication intact when it is
rate limited. Methods with their own catch-all (for example
`period_usage_and_costs()`, `month_insights()`, the `enode_*` and
`smart_batteries*` methods, and the mutations) retain their existing
return-on-error or rewrap contracts; this is not a promise that every public
method propagates all request exceptions.

`validate_authentication()` returns `False` when authentication is absent or
rejected. If renewing an expired token is rate limited, it now raises
`RateLimitException` instead of returning `False`; the existing tokens remain
intact. Callers must treat that exception as a temporary API failure rather
than a request to enter credentials again.

The client does not sleep, automatically replay a request, or impose a global
cooldown. Callers can schedule a later update using `retry_after`, or use their
configured polling policy when it is `None`. Mutation retries require an
explicit decision by the caller.

`retry_after` has no application-specific maximum. A scheduler with a bounded
horizon can wait in bounded chunks while keeping the request deferred until
the server-provided delay has elapsed. Do not shorten that delay by clamping
it and retrying earlier. A value of `0` (or an expired HTTP-date) means
"now"; schedulers that treat `0` as an immediate retry should fall back to
their normal interval instead.

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
