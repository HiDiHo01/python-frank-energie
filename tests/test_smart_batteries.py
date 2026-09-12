"""Tests for Frank Energie Smart batteries implementation."""

from datetime import UTC, datetime

import aiohttp
import pytest
from syrupy.assertion import SnapshotAssertion

from python_frank_energie import FrankEnergie

from . import load_fixtures

SIMPLE_DATA_URL = "frank-graphql-prod.graphcdn.app"


@pytest.mark.asyncio
async def test_smart_batteries(aresponses, snapshot: SnapshotAssertion):
    """Test request with authentication."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("smart_batteries.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        smart_batteries = await api.smart_batteries()
        await api.close()

    assert smart_batteries is not None
    assert smart_batteries == snapshot


@pytest.mark.asyncio
async def test_smart_battery_sessions(aresponses, snapshot: SnapshotAssertion):
    """Test request with authentication."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("smart_battery_sessions.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        sessions = await api.smart_battery_sessions("device_id", datetime.now(UTC), datetime.now(UTC))
        await api.close()

    assert sessions is not None
    assert sessions == snapshot


@pytest.mark.asyncio
async def test_smart_battery_details_not_found():
    """Test smart_battery_details returns None when battery is not found."""
    from unittest.mock import patch
    from python_frank_energie.exceptions import SmartBatteryNotFoundException

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        with patch.object(
            api,
            "_query",
            side_effect=SmartBatteryNotFoundException("smart-battery-error:battery-not-found"),
        ):
            result = await api.smart_battery_details("missing_device")
            assert result is None


@pytest.mark.asyncio
async def test_smart_battery_sessions_not_found():
    """Test smart_battery_sessions returns None when battery is not found."""
    from unittest.mock import patch
    from python_frank_energie.exceptions import SmartBatteryNotFoundException

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        with patch.object(
            api,
            "_query",
            side_effect=SmartBatteryNotFoundException("smart-battery-error:battery-not-found"),
        ):
            result = await api.smart_battery_sessions(
                "missing_device",
                datetime.now(UTC),
                datetime.now(UTC),
            )
            assert result is None
