# Authentication

## Overview

The Frank Energie API uses JWT-based authentication.

Authentication is established through the `login` mutation, which returns:

- `authToken` (access token)
- `refreshToken` (refresh token)

These values are stored in the `Authentication` model.

## Token Expiration

The `Authentication` model extracts the JWT `exp` claim from the access token and stores it in `expires_at`.

The model exposes `Authentication.is_expired`, which returns `True` when the token has expired or when expiration information cannot be determined.

An expired access token does not necessarily mean the user session is invalid. A valid refresh token may still be available and should be used to obtain a new access token.

## Authentication State

`FrankEnergie.is_authenticated()` intentionally performs a lightweight local credential check.

It verifies that authentication credentials are available and suitable for token renewal. It does not validate token expiration or perform a network request.

This separation is intentional:

- `is_authenticated()` is a cheap local check.
- `validate_authentication()` performs server-side validation.
- `_query()` is responsible for renewing expired access tokens before sending requests.

## Important Design Decision

Do not make `FrankEnergie.is_authenticated()` depend solely on token expiration.

Doing so would cause valid sessions to become unauthenticated immediately when the access token expires, even though a valid refresh token may still be available.

This would force Home Assistant users into unnecessary reauthentication flows.

## Current Authentication Lifecycle

Current request flow:

API request
→ Access token expired?
→ renew_token()
→ Token renewal successful?
→ Continue request

Only when token renewal fails should the client be considered unauthenticated.

API request
→ Access token expired
→ renew_token()
→ Renewal failed
→ Raise AuthRequiredException
→ Home Assistant reauthentication flow

## Home Assistant Integration

The Home Assistant integration stores both access and refresh tokens and relies on the library to manage authentication state.

Preferred user experience:

1. Access token expires.
2. Library automatically renews the token.
3. Requests continue normally.
4. Reauthentication is requested only if renewal fails.

## Future Improvements

Potential improvements:

- Refresh-before-expiry window (for example 5 minutes before expiration).
- Token redaction in debug logging.
- Centralized authentication state management.
- Automatic retry when a request fails because a token becomes invalid unexpectedly.