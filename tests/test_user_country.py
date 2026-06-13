"""Tests for user_country API."""

from __future__ import annotations

import aiohttp
import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthRequiredException

from . import load_fixtures

SIMPLE_DATA_URL = "frank-graphql-prod.graphcdn.app"


@pytest.mark.asyncio
async def test_user_country(aresponses):
    """Test user_country request."""

    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("me.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(
            session,
            auth_token="a",
            refresh_token="b",
        )  # noqa: S106

        me = await api.user_country()

        await api.close()

    assert me.countryCode == "NL"


@pytest.mark.asyncio
async def test_user_country_without_authentication():
    """Test user_country without authentication."""

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)

        with pytest.raises(AuthRequiredException):
            await api.user_country()

        await api.close()
