"""Tests for Frank Energie Smart batteries implementation."""

import json
from datetime import UTC, datetime
from unittest.mock import patch

import aiohttp
import pytest
from syrupy.assertion import SnapshotAssertion

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import NetworkError, RateLimitException

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


@pytest.mark.asyncio
async def test_smart_battery_settings(aresponses, snapshot: SnapshotAssertion):
    """Test the per-battery adjustable settings, options and update windows."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("smart_battery_settings.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        settings = await api.smart_battery_settings("device_id")
        await api.close()

    assert settings is not None
    assert settings == snapshot


@pytest.mark.asyncio
async def test_smart_battery_settings_not_found(aresponses):
    """Test the real battery-not-found GraphQL error maps to None."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=json.dumps(
                {
                    "data": None,
                    "errors": [{"message": "smart-battery-error:battery-not-found", "path": ["smartBatterySettings"]}],
                }
            ),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        result = await api.smart_battery_settings("missing_device")
        await api.close()

    assert result is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [RateLimitException("SmartBatterySettings"), NetworkError("Frank Energie API timeout")],
    ids=["rate-limit", "network"],
)
async def test_smart_battery_settings_propagates_request_failures(error):
    """Request failures propagate so callers can back off or retry instead of seeing 'no settings'."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        with (
            patch.object(api, "_query", side_effect=error),
            pytest.raises(type(error)),
        ):
            await api.smart_battery_settings("device_id")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        {
            "data": {"smartBatterySettings": {"imbalanceTradingStrategy": None, "lockedForUpdatesTill": None}},
            "errors": [{"message": "Something failed", "path": ["smartBatterySettings", "imbalanceTradingStrategy"]}],
        },
        {"data": {"smartBatterySettings": {"lockedForUpdatesTill": "tomorrow"}}},
        {"data": {"smartBatterySettings": {"lockedForUpdatesTill": "2026-11-05T23:00:00"}}},
        {"data": {"smartBatterySettings": {"lockedForUpdatesTill": "2026-11-05"}}},
        None,
        {"data": None},
        {"data": {"smartBatterySettings": None}},
        {"data": {"smartBatterySettings": {"batteryMode": {"current": "TRADING", "options": []}}}},
        {"data": {"smartBatterySettings": {"batteryMode": {"current": "TRADING", "updatable": True, "options": {}}}}},
        {
            "data": {
                "smartBatterySettings": {
                    "selfConsumptionTradingThresholdPrice": {
                        "current": 0.2,
                        "updatable": True,
                        "options": [{"amount": "0.2"}],
                    }
                }
            }
        },
        {
            "data": {
                "smartBatterySettings": {
                    "selfConsumptionTradingThresholdPrice": {
                        "current": 0.2,
                        "updatable": True,
                        "options": [{"amount": 10**400}],
                    }
                }
            }
        },
    ],
    ids=[
        "graphql-errors",
        "bad-datetime",
        "datetime-without-timezone",
        "date-only",
        "no-response",
        "no-data",
        "no-settings",
        "missing-updatable",
        "options-not-a-list",
        "non-numeric-amount",
        "amount-too-large-for-float",
    ],
)
async def test_smart_battery_settings_missing_or_malformed(response):
    """Test smart_battery_settings returns None instead of guessing on a bad response."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        with patch.object(api, "_query", return_value=response):
            assert await api.smart_battery_settings("device_id") is None
