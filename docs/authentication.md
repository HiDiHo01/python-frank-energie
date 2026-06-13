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

## Important Design Decision

Do not make `FrankEnergie.is_authenticated()` depend solely on token expiration unless automatic token renewal is implemented.

Changing authentication checks from a simple authentication-object existence check to a strict expiration check without automatic renewal will cause valid sessions to fail immediately when the access token expires.

This would force Home Assistant users into unnecessary reauthentication flows even when a valid refresh token is available.

## Expected Authentication Lifecycle

Recommended flow:

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

- Automatic token renewal inside request handling.
- Refresh-before-expiry window (for example 5 minutes before expiration).
- Token redaction in debug logging.
- Centralized authentication state management.
