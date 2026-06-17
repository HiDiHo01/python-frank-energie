"""Tests for renew_token authentication."""

from __future__ import annotations

import aiohttp
import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.authentication import Authentication
from python_frank_energie.exceptions import AuthException

from . import load_fixtures

SIMPLE_DATA_URL = "frank-graphql-prod.graphcdn.app"


@pytest.mark.asyncio
async def test_renew_token_success(aresponses):
    """Test successful token renewal."""

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
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106

        auth = await api.renew_token()

        assert api.is_authenticated is True
        assert auth.authToken == "hello"
        assert auth.refreshToken == "world"

        await api.close()


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_renew_token_no_auth_header(aresponses):
    """Test that renew_token does not send the Authorization header."""

    async def response_handler(request):
        assert "Authorization" not in request.headers
        return aresponses.Response(
            text=load_fixtures("authentication.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        )

    aresponses.add(SIMPLE_DATA_URL, "/", "POST", response_handler)

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        api._auth = Authentication(
            auth_token="expired_token",
            refresh_token="refresh_token",
        )

        auth = await api.renew_token()

        assert api.is_authenticated is True
        assert auth.authToken == "hello"
        assert auth.refreshToken == "world"

        await api.close()


@pytest.mark.asyncio
async def test_renew_token_invalid_credentials(aresponses):
    """Test token renewal with invalid credentials."""

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
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106

        with pytest.raises(AuthException):
            await api.renew_token()

        await api.close()


@pytest.mark.asyncio
async def test_renew_token_invalid_response(aresponses):
    """Test token renewal with invalid response."""

    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text="{}",
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106

        with pytest.raises(AuthException):
            await api.renew_token()

        await api.close()


@pytest.mark.asyncio
async def test_renew_token_logging(aresponses, caplog):
    """Test that authentication and renewal decisions generate debug log statements."""
    import logging
    from datetime import UTC, datetime, timedelta

    from python_frank_energie.models import Authentication as ModelsAuth

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
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106

        # Set an auth token with a known expires_at in the future
        future_expiry = datetime.now(UTC) + timedelta(minutes=10)
        api._auth = ModelsAuth(
            authToken="a.b.c",
            refreshToken="b",
            expires_at=future_expiry,
            version=None,
        )

        with caplog.at_level(logging.DEBUG):
            # Validate authentication (should log the expiry check but NOT log renewal required)
            await api.validate_authentication()

            # Now set to expired in the past
            expired_time = datetime.now(UTC) - timedelta(minutes=10)
            api._auth = ModelsAuth(
                authToken="a.b.c",
                refreshToken="b",
                expires_at=expired_time,
                version=None,
            )

            await api.validate_authentication()

        # Check logs
        assert any("Token expiry check: now=" in record.message for record in caplog.records)
        assert any("Token renewal required: expires_at=" in record.message for record in caplog.records)
        assert any("Authentication token updated; expires_at=" in record.message for record in caplog.records)

        await api.close()
