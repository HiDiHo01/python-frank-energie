# Authentication

## Overview

Use `FrankEnergie(auth_token=..., refresh_token=...)` to start with credentials
from the caller, or `await client.login(username, password)` to obtain them.
The active credential object and the results of `login()` and `renew_token()`
use `python_frank_energie.models.Authentication`. See the
[comparison of authentication models](ARCHITECTURE.md#the-two-authentication-models)
for the separate package-exported class.

## Token expiration

The runtime model extracts the JWT `exp` claim into UTC expiry metadata when
available. With a known access-token expiry, the client starts renewal checks
five minutes before expiration. With unknown expiry, a nonempty token with at
least three dot-separated parts is due for renewal. The refresh-token expiry
is exposed as metadata. The provider determines whether it accepts either token.

## Authentication state

`client.is_authenticated` is a property. It checks for a nonempty access token
in the current credential object. A token can be due for renewal and still
satisfy this local check.

`await client.validate_authentication()` returns `False` if that local check
fails or renewal raises `AuthException` or `AuthRequiredException`. It checks
expiry and renews when necessary. Request failures such as `RateLimitException`
and `NetworkError` can propagate.

## Current authentication lifecycle

1. Before sending an operation, the client checks whether the access token is
   due for renewal. The `RenewToken` operation skips this check.
2. If renewal is needed, header preparation takes the per-client lock and
   checks expiry again. A successful renewal installs the returned credentials.
3. The operation proceeds with the current access token. A renewal failure
   prevents that request from being sent. Subsequent error handling depends on
   the public method.

`renew_token()` clears the credential object when the renewal request raises
`RefreshTokenInvalidException`. A rate-limited renewal keeps it intact. See
[rate-limit errors](rate-limits.md) for the retry hint. A successful
`logout()` also clears the credential object.

## Concurrent renewal protection

Automatic renewal during header preparation and expiry checks in
`validate_authentication()` share the same lock. Waiting requests check the
current credentials after acquiring it. An explicit `renew_token()` call
bypasses the lock.

## Authorization headers

When the credential object exists, the client adds a bearer authorization
header to GraphQL requests. `RenewToken` skips the automatic bearer header and
passes the current tokens as mutation variables.

## Home Assistant integration

Credential persistence, reauthentication flows, and retry scheduling are
responsibilities of the consuming application. A temporary request failure,
including a rate limit during renewal, is distinct from rejected credentials.
See the [Home Assistant boundary](ARCHITECTURE.md#home-assistant-boundary).
