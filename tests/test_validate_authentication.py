"""Regression tests for locally consistent authentication validation."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import (
    AuthException,
    AuthRequiredException,
    NetworkError,
    RateLimitException,
    RefreshTokenInvalidException,
)
from python_frank_energie.models import Authentication


def _client_with_expired_credentials() -> FrankEnergie:
    """Create a client with fictitious expired credentials and no HTTP session."""
    client = FrankEnergie()
    client._auth = Authentication(
        authToken="synthetic-expired-access",
        refreshToken="synthetic-refresh",
        version=None,
        token_expires_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("access_token", "expected"),
    [(None, False), ("", False), ("synthetic-valid-access", True)],
)
async def test_validate_authentication_without_expired_credentials(
    access_token: str | None, expected: bool
) -> None:
    """Return local status without making a renewal request."""
    client = FrankEnergie()
    if access_token is not None:
        client._auth = Authentication(
            authToken=access_token,
            refreshToken="synthetic-refresh",
            version=None,
            token_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

    with patch.object(client, "renew_token") as renewal:
        assert await client.validate_authentication() is expected

    renewal.assert_not_awaited()


@pytest.mark.asyncio
async def test_validate_authentication_renews_expired_credentials_once() -> None:
    """Install renewed credentials and report local authentication success."""
    client = _client_with_expired_credentials()
    response = {
        "data": {
            "renewToken": {
                "authToken": "synthetic-renewed-access",
                "refreshToken": "synthetic-renewed-refresh",
            }
        }
    }

    with patch.object(client, "_query", return_value=response) as request:
        assert await client.validate_authentication() is True

    request.assert_awaited_once()
    assert client._auth is not None
    assert client._auth.authToken == "synthetic-renewed-access"


@pytest.mark.asyncio
async def test_validate_authentication_concurrent_rejected_refresh() -> None:
    """Both waiting validations must fail after the first clears credentials."""
    client = _client_with_expired_credentials()
    renewal_started = asyncio.Event()
    finish_renewal = asyncio.Event()
    second_started = asyncio.Event()

    async def reject_refresh(_query: object) -> dict[str, object]:
        """Block renewal until another validation is waiting, then reject it."""
        renewal_started.set()
        await finish_renewal.wait()
        raise RefreshTokenInvalidException("synthetic invalid refresh token")

    async def validate_second() -> bool:
        """Signal that a second validation has been scheduled."""
        second_started.set()
        return await client.validate_authentication()

    with patch.object(client, "_query", side_effect=reject_refresh) as request:
        async with asyncio.TaskGroup() as group:
            first = group.create_task(client.validate_authentication())
            await asyncio.wait_for(renewal_started.wait(), timeout=5)
            second = group.create_task(validate_second())
            await asyncio.wait_for(second_started.wait(), timeout=5)
            await asyncio.sleep(0)
            finish_renewal.set()

    assert (first.result(), second.result()) == (False, False)
    assert client._auth is None
    request.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_authentication_concurrent_successful_refresh() -> None:
    """Waiting validators share a single successful renewal request."""
    client = _client_with_expired_credentials()
    renewal_started = asyncio.Event()
    finish_renewal = asyncio.Event()
    response = {
        "data": {
            "renewToken": {
                "authToken": "synthetic-renewed-access",
                "refreshToken": "synthetic-renewed-refresh",
            }
        }
    }

    async def complete_refresh(_query: object) -> dict[str, object]:
        """Hold the initial renewal until the other validator is scheduled."""
        renewal_started.set()
        await finish_renewal.wait()
        return response

    with patch.object(client, "_query", side_effect=complete_refresh) as request:
        async with asyncio.TaskGroup() as group:
            first = group.create_task(client.validate_authentication())
            await asyncio.wait_for(renewal_started.wait(), timeout=5)
            second = group.create_task(client.validate_authentication())
            await asyncio.sleep(0)
            finish_renewal.set()

    assert (first.result(), second.result()) == (True, True)
    assert client.is_authenticated is True
    request.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_authentication_checks_credentials_after_renewal() -> None:
    """Never return success if renewal leaves the local credential state empty."""
    client = _client_with_expired_credentials()

    async def clear_credentials() -> None:
        """Simulate the credential state being cleared during renewal."""
        client._auth = None

    with patch.object(client, "renew_token", side_effect=clear_credentials) as renewal:
        assert await client.validate_authentication() is False

    renewal.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [AuthException("synthetic rejected credentials"), AuthRequiredException("synthetic authentication required")],
)
async def test_validate_authentication_rejected_renewal_returns_false(error: Exception) -> None:
    """Keep typed authentication rejections as a False result."""
    client = _client_with_expired_credentials()

    with patch.object(client, "renew_token", side_effect=error) as renewal:
        assert await client.validate_authentication() is False

    renewal.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [RateLimitException("RenewToken", retry_after=120.0), NetworkError("synthetic network failure")],
)
async def test_validate_authentication_request_errors_propagate(error: Exception) -> None:
    """Propagate request failures without clearing existing credentials."""
    client = _client_with_expired_credentials()
    previous_auth = client._auth

    with (
        patch.object(client, "renew_token", side_effect=error) as renewal,
        pytest.raises(type(error)) as raised,
    ):
        await client.validate_authentication()

    assert raised.value is error
    assert client._auth is previous_auth
    renewal.assert_awaited_once()


@pytest.mark.asyncio
async def test_validate_authentication_propagates_cancellation() -> None:
    """Do not swallow asyncio cancellation while renewing the access token."""
    client = _client_with_expired_credentials()

    with (
        patch.object(client, "renew_token", side_effect=asyncio.CancelledError()) as renewal,
        pytest.raises(asyncio.CancelledError),
    ):
        await client.validate_authentication()

    renewal.assert_awaited_once()
