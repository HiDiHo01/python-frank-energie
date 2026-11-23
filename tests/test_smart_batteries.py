"""Tests for Frank Energie Smart batteries implementation."""

import json
import logging
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import aiohttp
import pytest
from syrupy.assertion import SnapshotAssertion

from python_frank_energie import FrankEnergie
from python_frank_energie.domain import SmartBatteryMode, SmartBatteryStatus, SmartBatteryTradingAlgorithm
from python_frank_energie.exceptions import AuthException, AuthRequiredException, NetworkError, RateLimitException
from python_frank_energie.models import SmartBatterySessions, SmartBatterySummary

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
async def test_smart_battery_sessions(aresponses, snapshot: SnapshotAssertion) -> None:
    """Test request with authentication."""
    requests: list[dict[str, Any]] = []

    async def handler(request: Any) -> Any:
        requests.append(await request.json())
        return aresponses.Response(
            text=load_fixtures("smart_battery_sessions.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        )

    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        handler,
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        sessions = await api.smart_battery_sessions("device_id", datetime.now(UTC), datetime.now(UTC))
        await api.close()

    assert sessions is not None
    assert sessions == snapshot
    query = requests[0]["query"]
    assert requests[0]["operationName"] == "SmartBatterySessions"
    for field_name in (
        "periodBreakdownTradingResult",
        "periodBreakdownFrankSlim",
        "periodResult",
        "periodBreakdownEpexCorrection",
        "date",
        "result",
        "status",
    ):
        assert field_name in query


def test_smart_battery_sessions_period_breakdowns_preserve_signed_zero_and_missing_values() -> None:
    """Parse new period fields without changing signs or collapsing null and zero."""
    sessions = SmartBatterySessions.from_dict(
        {
            "data": {
                "smartBatterySessions": {
                    "deviceId": "synthetic-device",
                    "periodBreakdownTradingResult": 0,
                    "periodBreakdownFrankSlim": None,
                    "periodBreakdownEpexCorrection": 0.0009,
                    "sessions": [
                        {
                            "date": "2026-11-16",
                            "result": 0,
                            "status": "COMPLETE_FINAL",
                        }
                    ],
                }
            }
        }
    )

    assert sessions.period_breakdown_trading_result == pytest.approx(0.0)
    assert sessions.period_breakdown_frank_slim is None
    assert sessions.period_result is None
    assert sessions.period_breakdown_epex_correction == pytest.approx(0.0009)
    assert sessions.sessions[0].date.isoformat() == "2026-11-16T00:00:00+00:00"
    assert sessions.sessions[0].result == pytest.approx(0.0)
    assert sessions.sessions[0].status.value == "COMPLETE_FINAL"


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
    requests: list[dict] = []

    async def handler(request):
        requests.append(await request.json())
        return aresponses.Response(
            text=load_fixtures("smart_battery_settings.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        )

    aresponses.add(SIMPLE_DATA_URL, "/", "POST", handler)

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        settings = await api.smart_battery_settings("device_id")
        await api.close()

    assert [(r["operationName"], r["variables"]) for r in requests] == [
        ("SmartBatterySettings", {"deviceId": "device_id"})
    ]
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
    [
        AuthException("Not authorized"),
        AuthRequiredException("Authentication required"),
        RateLimitException("SmartBatterySettings"),
        NetworkError("Frank Energie API timeout"),
    ],
    ids=["auth", "auth-required", "rate-limit", "network"],
)
async def test_smart_battery_settings_propagates_request_failures(error):
    """Request failures propagate so callers can reauthenticate, back off or retry instead of seeing 'no settings'."""
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
        {"data": {"smartBatterySettings": {"batteryMode": {"current": "TRADING", "updatable": True}}}},
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
        "missing-options",
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


def _details_response(trading_algorithm_field: dict) -> str:
    """Build a SmartBattery response whose settings carry the given tradingAlgorithm field."""
    return json.dumps(
        {
            "data": {
                "smartBattery": {
                    "brand": "Sessy",
                    "capacity": 5.2,
                    "id": "device_id",
                    "settings": {
                        "batteryMode": "IMBALANCE_TRADING",
                        "imbalanceTradingStrategy": "AGGRESSIVE",
                        "selfConsumptionTradingAllowed": True,
                        "selfConsumptionTradingThresholdPrice": 0.2,
                        **trading_algorithm_field,
                    },
                },
                "smartBatterySummary": {
                    "lastKnownStateOfCharge": 50,
                    "lastKnownStatus": "ONLINE",
                    "lastUpdate": "2026-11-05T08:00:00.000Z",
                    "totalResult": 1.5,
                },
            }
        }
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("trading_algorithm_field", "expected"),
    [
        ({"tradingAlgorithm": "T1"}, SmartBatteryTradingAlgorithm.T1),
        ({"tradingAlgorithm": "T2"}, SmartBatteryTradingAlgorithm.T2),
        ({"tradingAlgorithm": "T3"}, SmartBatteryTradingAlgorithm.T3),
        ({"tradingAlgorithm": "t3"}, SmartBatteryTradingAlgorithm.T3),
        ({"tradingAlgorithm": "T4"}, SmartBatteryTradingAlgorithm.UNKNOWN),
        ({"tradingAlgorithm": None}, None),
        ({}, None),
    ],
    ids=["t1", "t2", "t3", "t3-lowercase", "unknown", "null", "absent"],
)
async def test_smart_battery_details_trading_algorithm(aresponses, trading_algorithm_field, expected):
    """smart_battery_details preserves known, future, null, and absent trading algorithms."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=_details_response(trading_algorithm_field),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        details = await api.smart_battery_details("device_id")
        await api.close()

    assert details is not None
    assert details.smart_battery.settings is not None
    assert details.smart_battery.settings.battery_mode is SmartBatteryMode.IMBALANCE_TRADING
    assert details.smart_battery.settings.trading_algorithm is expected


@pytest.mark.asyncio
async def test_smart_battery_settings_are_per_device(aresponses):
    """Each device gets its own options: requests carry their own deviceId and
    two batteries with different options never share them."""
    responses = {
        "battery_t2": {
            "batteryMode": {
                "current": "SELF_CONSUMPTION_MIX",
                "updatable": True,
                "options": [
                    {"code": "IMBALANCE_TRADING", "selectable": True},
                    {"code": "SELF_CONSUMPTION_MIX", "selectable": True},
                ],
            },
        },
        "battery_t1": {
            "batteryMode": {
                "current": "TRADING",
                "updatable": True,
                "options": [
                    {"code": "TRADING", "selectable": True},
                    {"code": "SELF_CONSUMPTION", "selectable": True},
                ],
            },
        },
    }

    async def handler(request):
        device_id = (await request.json())["variables"]["deviceId"]
        return aresponses.Response(
            text=json.dumps({"data": {"smartBatterySettings": responses[device_id]}}),
            status=200,
            headers={"Content-Type": "application/json"},
        )

    aresponses.add(SIMPLE_DATA_URL, "/", "POST", handler)
    aresponses.add(SIMPLE_DATA_URL, "/", "POST", handler)

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        t2 = await api.smart_battery_settings("battery_t2")
        t1 = await api.smart_battery_settings("battery_t1")
        await api.close()

    assert t2 is not None
    assert t2.battery_mode is not None
    assert t1 is not None
    assert t1.battery_mode is not None
    assert [option.code for option in t2.battery_mode.options] == [
        SmartBatteryMode.IMBALANCE_TRADING,
        SmartBatteryMode.SELF_CONSUMPTION_MIX,
    ]
    assert [option.code for option in t1.battery_mode.options] == [
        SmartBatteryMode.TRADING,
        SmartBatteryMode.SELF_CONSUMPTION,
    ]


@pytest.mark.parametrize(
    ("raw_status", "expected_status", "diagnostic"),
    [
        ("CHARGE_INTRADAY", SmartBatteryStatus.CHARGE_INTRADAY, None),
        ("charge_intraday", SmartBatteryStatus.CHARGE_INTRADAY, None),
        ("UNKNOWN", SmartBatteryStatus.UNKNOWN, "UNKNOWN"),
        ("CHARGING", SmartBatteryStatus.UNKNOWN, "CHARGING"),
        ("CHARGE_SOLAR", SmartBatteryStatus.UNKNOWN, "CHARGE_SOLAR"),
        ("", SmartBatteryStatus.UNKNOWN, "<empty>"),
        (None, SmartBatteryStatus.UNKNOWN, "<null>"),
        ({"deviceId": "sensitive-device-12345"}, SmartBatteryStatus.UNKNOWN, "<invalid-type>"),
        ("STATUS_ACCOUNT_SECRET123", SmartBatteryStatus.UNKNOWN, "<redacted>"),
    ],
)
def test_smart_battery_summary_status_diagnostics(
    raw_status: object,
    expected_status: SmartBatteryStatus,
    diagnostic: str | None,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Log only safe original status tokens once, before enum fallback."""
    from python_frank_energie import models

    monkeypatch.setattr(models, "_LOGGED_BATTERY_STATUS_DIAGNOSTICS", set())
    payload = {
        "lastKnownStateOfCharge": 62,
        "lastKnownStatus": raw_status,
        "lastUpdate": "2026-11-23T10:38:25Z",
        "totalResult": 1.0,
        "deviceId": "sensitive-device-12345",
    }
    with caplog.at_level(logging.WARNING, logger="python_frank_energie.models"):
        summary = SmartBatterySummary.from_dict(payload)
        repeated_summary = SmartBatterySummary.from_dict(payload)

    assert summary.last_known_status is expected_status
    assert repeated_summary.last_known_status is expected_status
    assert summary.last_update == datetime(2026, 11, 23, 10, 38, 25, tzinfo=UTC)
    messages = [
        record.getMessage()
        for record in caplog.records
        if "SmartBatterySummary raw lastKnownStatus before enum conversion:" in record.getMessage()
    ]
    expected_messages = (
        [f"SmartBatterySummary raw lastKnownStatus before enum conversion: {diagnostic}"]
        if diagnostic is not None
        else []
    )
    assert messages == expected_messages
    assert "sensitive-device-12345" not in caplog.text
    assert "STATUS_ACCOUNT_SECRET123" not in caplog.text


def test_smart_battery_summary_missing_status_diagnostic(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Distinguish an absent status field from an explicit API null."""
    from python_frank_energie import models

    monkeypatch.setattr(models, "_LOGGED_BATTERY_STATUS_DIAGNOSTICS", set())
    payload = {
        "lastKnownStateOfCharge": 62,
        "lastUpdate": "2026-11-23T10:38:25Z",
        "totalResult": 1.0,
    }
    with caplog.at_level(logging.WARNING, logger="python_frank_energie.models"):
        summary = SmartBatterySummary.from_dict(payload)

    assert summary.last_known_status is SmartBatteryStatus.UNKNOWN
    assert "SmartBatterySummary raw lastKnownStatus before enum conversion: <missing>" in caplog.text
