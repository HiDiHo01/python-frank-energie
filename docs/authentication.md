# Authentication

## Overview

The Frank Energie API uses JWT-based authentication.

The `login` mutation returns two tokens.

- `authToken` (access token)
- `refreshToken` (refresh token)

The client stores these values in `python_frank_energie.models.Authentication`.
It can also start with tokens provided through its constructor. See the
[comparison of authentication models](ARCHITECTURE.md#the-two-authentication-models)
for the separate package-exported class.

## Token Expiration

The runtime model extracts the JWT `exp` claim into UTC expiry metadata
when available. Its `is_expired` property uses a five-minute renewal margin.
With unknown expiry, a nonempty access token with at least three dot-separated
parts is due for renewal. Refresh-token expiry is exposed as metadata.

## Authentication State

`FrankEnergie.is_authenticated` is a property that checks for a nonempty
access token in the current credential object.

`await client.validate_authentication()` checks local credential presence
under the per-client renewal lock. It returns `False` if credentials are absent
or renewal raises `AuthException` or `AuthRequiredException`. Request failures
such as `RateLimitException` and `NetworkError` can propagate.
It returns `True` only when a nonempty local access token is present after
any required renewal. When renewal is not due, it makes no provider request.
Consequently, `True` does not prove that the provider still accepts the token:
a revoked but not-yet-expired token can pass this local check.

When validation calls overlap, a waiting call rechecks credentials after
acquiring the renewal lock. If an earlier validation cleared them after an
invalid refresh token (`RefreshTokenInvalidException`), the waiting call
returns `False`. This lock protects coordinated automatic renewal, not
concurrent direct calls to `renew_token()` or `logout()`; those interactions
are outside the scope of this local validation guarantee.

## Important Design Decision

Keep the local authentication check independent of expiry so the client can
renew an expired access token.

## Current Authentication Lifecycle

1. Before sending an operation, the client checks whether the access token
   is due for renewal. The `RenewToken` operation skips this check.
2. A successful renewal installs the returned credentials and lets the
   original request proceed. A renewal failure prevents that request from
   being sent.

A renewal request that raises `RefreshTokenInvalidException` clears the
credential object. A rate-limited renewal keeps it intact. See
[rate-limit errors](rate-limits.md) for the retry hint. A successful
`logout()` also clears the credential object.

## Concurrent Renewal Protection

Header preparation and `validate_authentication()` share a per-client lock
and check expiry after acquiring it. Direct `renew_token()` calls bypass
that lock.

## Authorization Headers

When the credential object exists, GraphQL operations automatically receive
the current access token in the bearer header.

```text
Authorization: Bearer <authToken>
```

The `RenewToken` operation is exempt from authenticated-header injection and token-refresh prechecks to avoid recursive renewal loops.

## Home Assistant Integration

The consuming application owns credential persistence, reauthentication, and
retry scheduling. After an operation that may automatically renew credentials,
applications must persist both **current** tokens, not just the original
`login()` result: `renew_token()` replaces the client's credential object,
while the operation triggering automatic renewal does not return the new pair.

Currently, the instance's deprecated `client.auth` property exposes that
current `Authentication` object (and emits a deprecation error log). Its
`authToken` and `refreshToken` fields contain the current values. The public
`client.access_token` and `client.refresh_token` attributes are initialization-
only placeholders and do **not** track renewed credentials. There is currently
no nondeprecated public getter for both current tokens. An explicit
`await client.renew_token()` returns the renewed object, but should not be
invoked solely to inspect token values. Applications should store both values
securely and consistently after a possible renewal, never in diagnostics or
logs. See the [Home Assistant boundary](ARCHITECTURE.md#home-assistant-boundary).

## Security Considerations

JWT expiration timestamps are parsed and stored locally. They guide renewal
timing. The provider determines whether it accepts the token.

## Future Improvements

See the [proposed refactoring sequence](ARCHITECTURE.md#proposed-refactoring-sequence).
