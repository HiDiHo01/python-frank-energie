"""Tests for login authentication."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import aiohttp
import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthException, NetworkError

from . import load_fixtures

SIMPLE_DATA_URL = "frank-graphql-prod.graphcdn.app"


@pytest.mark.asyncio
async def test_login_success(aresponses):
    """Test successful login."""

    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("authentication.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)

        auth = await api.login("a", "b")  # noqa: S106

        assert api.is_authenticated is True
        assert auth.authToken == "hello"
        assert auth.refreshToken == "world"

        await api.close()


@pytest.mark.asyncio
async def test_login_invalid_credentials(aresponses):
    """Test login with invalid credentials."""

    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("response_with_error.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)

        with pytest.raises(AuthException):
            await api.login("a", "b")  # noqa: S106

        await api.close()


@pytest.mark.asyncio
async def test_login_missing_username():
    """Test login without username."""

    api = FrankEnergie()

    with pytest.raises(ValueError, match="Username and password must be provided"):
        await api.login("", "password")


@pytest.mark.asyncio
async def test_login_missing_password():
    """Test login without password."""

    api = FrankEnergie()

    with pytest.raises(ValueError, match="Username and password must be provided"):
        await api.login("user@example.com", "")


@pytest.mark.parametrize(
    "transport_error",
    [TimeoutError("synthetic timeout"), aiohttp.ClientConnectionError("synthetic connection failure")],
    ids=["timeout", "connection_failure"],
)
@pytest.mark.asyncio
async def test_login_preserves_network_error(transport_error: Exception) -> None:
    """Keep transport failures distinct from rejected credentials without retrying."""
    session = MagicMock(spec=aiohttp.ClientSession)
    session.post.return_value.__aenter__.side_effect = transport_error
    client = FrankEnergie(session, auth_token="synthetic-token")  # noqa: S106
    original_auth = client._auth

    with (
        patch("python_frank_energie.frank_energie.Authentication.from_dict") as parser,
        pytest.raises(NetworkError) as raised,
    ):
        await client.login("synthetic-user", "synthetic-password")  # noqa: S106

    assert raised.value.__cause__ is transport_error
    assert client._auth is original_auth
    parser.assert_not_called()
    session.post.assert_called_once()
