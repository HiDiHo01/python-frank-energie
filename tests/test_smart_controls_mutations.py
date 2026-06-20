"""Tests for smart controls mutation methods in FrankEnergie."""
# tests/test_smart_controls_mutations.py

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthRequiredException

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_api() -> FrankEnergie:
    """Return an authenticated FrankEnergie instance."""
    return FrankEnergie(auth_token="test-token", refresh_token="test-refresh")


# ---------------------------------------------------------------------------
# disable_smart_trading
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_smart_trading_returns_true_on_success():
    api = _make_api()
    mock_response = {"data": {"disableSmartTrading": {"success": True}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_trading()
    assert result is True


@pytest.mark.asyncio
async def test_disable_smart_trading_returns_false_when_success_false():
    api = _make_api()
    mock_response = {"data": {"disableSmartTrading": {"success": False}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_trading()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_trading_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Not authorised"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_trading()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_trading_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError("timeout"))):
        result = await api.disable_smart_trading()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_trading_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.disable_smart_trading()


@pytest.mark.asyncio
async def test_disable_smart_trading_sends_correct_operation_name():
    api = _make_api()
    mock_response = {"data": {"disableSmartTrading": {"success": True}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.disable_smart_trading()
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "DisableSmartTrading"
    assert "disableSmartTrading" in called_query.query


# ---------------------------------------------------------------------------
# disable_smart_feed_in
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_smart_feed_in_returns_true_on_success():
    api = _make_api()
    mock_response = {"data": {"smartFeedInDisable": {"success": True}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_feed_in()
    assert result is True


@pytest.mark.asyncio
async def test_disable_smart_feed_in_returns_false_when_success_false():
    api = _make_api()
    mock_response = {"data": {"smartFeedInDisable": {"success": False}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_feed_in()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_feed_in_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Not authorised"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_feed_in()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_feed_in_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError)):
        result = await api.disable_smart_feed_in()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_feed_in_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.disable_smart_feed_in()


@pytest.mark.asyncio
async def test_disable_smart_feed_in_sends_correct_operation_name():
    api = _make_api()
    mock_response = {"data": {"smartFeedInDisable": {"success": True}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.disable_smart_feed_in()
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "SmartFeedInDisable"
    assert "smartFeedInDisable" in called_query.query


# ---------------------------------------------------------------------------
# disable_smart_hvac
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_smart_hvac_returns_true_on_success():
    api = _make_api()
    mock_response = {"data": {"smartHvacDisable": {"success": True}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_hvac()
    assert result is True


@pytest.mark.asyncio
async def test_disable_smart_hvac_returns_false_when_success_false():
    api = _make_api()
    mock_response = {"data": {"smartHvacDisable": {"success": False}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_hvac()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_hvac_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Not authorised"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.disable_smart_hvac()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_hvac_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError)):
        result = await api.disable_smart_hvac()
    assert result is False


@pytest.mark.asyncio
async def test_disable_smart_hvac_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.disable_smart_hvac()


@pytest.mark.asyncio
async def test_disable_smart_hvac_sends_correct_operation_name():
    api = _make_api()
    mock_response = {"data": {"smartHvacDisable": {"success": True}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.disable_smart_hvac()
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "SmartHvacDisable"
    assert "smartHvacDisable" in called_query.query


# ---------------------------------------------------------------------------
# smart_hvac_update_settings
# ---------------------------------------------------------------------------


VALID_HVAC_SETTINGS = {"mode": "SMART", "temperatureLowerBound": 18.0, "temperatureUpperBound": 22.0}
HVAC_UPDATE_RESPONSE = {
    "data": {
        "smartHvacUpdateSettings": {
            "createdAt": "2026-01-01T00:00:00Z",
            "mode": "SMART",
            "temperatureLowerBound": 18.0,
            "temperatureUpperBound": 22.0,
            "updatedAt": "2026-05-28T12:00:00Z",
        }
    }
}


@pytest.mark.asyncio
async def test_smart_hvac_update_settings_returns_true_on_success():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(return_value=HVAC_UPDATE_RESPONSE)):
        result = await api.smart_hvac_update_settings("hvac-device-1", VALID_HVAC_SETTINGS)
    assert result is True


@pytest.mark.asyncio
async def test_smart_hvac_update_settings_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Device not found"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.smart_hvac_update_settings("hvac-device-1", VALID_HVAC_SETTINGS)
    assert result is False


@pytest.mark.asyncio
async def test_smart_hvac_update_settings_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError)):
        result = await api.smart_hvac_update_settings("hvac-device-1", VALID_HVAC_SETTINGS)
    assert result is False


@pytest.mark.asyncio
async def test_smart_hvac_update_settings_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.smart_hvac_update_settings("hvac-device-1", VALID_HVAC_SETTINGS)


@pytest.mark.asyncio
async def test_smart_hvac_update_settings_sends_correct_variables():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(return_value=HVAC_UPDATE_RESPONSE)) as mock_q:
        await api.smart_hvac_update_settings("hvac-device-1", VALID_HVAC_SETTINGS)
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "SmartHvacUpdateSettings"
    assert called_query.variables["deviceId"] == "hvac-device-1"
    assert called_query.variables["settings"] == VALID_HVAC_SETTINGS
    assert "temperatureLowerBound" in called_query.query
    assert "temperatureUpperBound" in called_query.query


# ---------------------------------------------------------------------------
# enode_update_vehicle_charge_settings
# ---------------------------------------------------------------------------


VALID_VEHICLE_INPUT = {
    "id": "charge-settings-123",
    "deadline": "2026-05-29T07:00:00+02:00",
    "isSmartChargingEnabled": True,
    "isSolarChargingEnabled": False,
    "minChargeLimit": 20,
    "maxChargeLimit": 80,
    "hourMonday": 7,
    "hourTuesday": 7,
    "hourWednesday": 7,
    "hourThursday": 7,
    "hourFriday": 7,
    "hourSaturday": 9,
    "hourSunday": 9,
}


@pytest.mark.asyncio
async def test_enode_update_vehicle_charge_settings_returns_true_on_success():
    api = _make_api()
    mock_response = {"data": {"enodeUpdateVehicleChargeSettings": None}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_update_vehicle_charge_settings(VALID_VEHICLE_INPUT)
    assert result is True


@pytest.mark.asyncio
async def test_enode_update_vehicle_charge_settings_raises_when_id_missing():
    api = _make_api()
    with pytest.raises(ValueError, match="'id' field"):
        await api.enode_update_vehicle_charge_settings({"deadline": "2026-05-29T07:00:00Z"})


@pytest.mark.asyncio
async def test_enode_update_vehicle_charge_settings_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Vehicle not found"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_update_vehicle_charge_settings(VALID_VEHICLE_INPUT)
    assert result is False


@pytest.mark.asyncio
async def test_enode_update_vehicle_charge_settings_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError)):
        result = await api.enode_update_vehicle_charge_settings(VALID_VEHICLE_INPUT)
    assert result is False


@pytest.mark.asyncio
async def test_enode_update_vehicle_charge_settings_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.enode_update_vehicle_charge_settings(VALID_VEHICLE_INPUT)


@pytest.mark.asyncio
async def test_enode_update_vehicle_charge_settings_sends_input_as_variable():
    api = _make_api()
    mock_response = {"data": {"enodeUpdateVehicleChargeSettings": None}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.enode_update_vehicle_charge_settings(VALID_VEHICLE_INPUT)
    called_query = mock_q.call_args[0][0]
    expected_input = {**VALID_VEHICLE_INPUT}
    expected_input["vehicleId"] = expected_input.pop("id")
    assert called_query.variables["input"] == expected_input
    assert called_query.operation_name == "EnodeUpdateVehicleChargeSettings"


@pytest.mark.asyncio
async def test_enode_update_vehicle_charge_settings_deadline_none_clears_target():
    """Passing deadline=None should be accepted (clears the target time)."""
    api = _make_api()
    mock_response = {"data": {"enodeUpdateVehicleChargeSettings": None}}
    input_no_deadline = {**VALID_VEHICLE_INPUT, "deadline": None}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_update_vehicle_charge_settings(input_no_deadline)
    assert result is True


# ---------------------------------------------------------------------------
# enode_update_charger_charge_settings
# ---------------------------------------------------------------------------


VALID_CHARGER_INPUT = {
    "id": "charger-settings-456",
    "deadline": "2026-05-29T07:00:00+02:00",
    "isSmartChargingEnabled": True,
    "isSolarChargingEnabled": False,
    "minChargeLimit": 10,
    "maxChargeLimit": 100,
    "hourMonday": 7,
    "hourTuesday": 7,
    "hourWednesday": 7,
    "hourThursday": 7,
    "hourFriday": 7,
    "hourSaturday": 9,
    "hourSunday": 9,
}


@pytest.mark.asyncio
async def test_enode_update_charger_charge_settings_returns_true_on_success():
    api = _make_api()
    mock_response = {"data": {"enodeUpdateChargerChargeSettings": None}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_update_charger_charge_settings(VALID_CHARGER_INPUT)
    assert result is True


@pytest.mark.asyncio
async def test_enode_update_charger_charge_settings_raises_when_id_missing():
    api = _make_api()
    with pytest.raises(ValueError, match="'id' field"):
        await api.enode_update_charger_charge_settings({"deadline": "2026-05-29T07:00:00Z"})


@pytest.mark.asyncio
async def test_enode_update_charger_charge_settings_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Charger not found"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_update_charger_charge_settings(VALID_CHARGER_INPUT)
    assert result is False


@pytest.mark.asyncio
async def test_enode_update_charger_charge_settings_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.enode_update_charger_charge_settings(VALID_CHARGER_INPUT)


@pytest.mark.asyncio
async def test_enode_update_charger_charge_settings_sends_correct_operation_name():
    api = _make_api()
    mock_response = {"data": {"enodeUpdateChargerChargeSettings": None}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.enode_update_charger_charge_settings(VALID_CHARGER_INPUT)
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "EnodeUpdateChargerChargeSettings"
    expected_input = {**VALID_CHARGER_INPUT}
    expected_input["chargerId"] = expected_input.pop("id")
    assert called_query.variables["input"] == expected_input


@pytest.mark.asyncio
async def test_enode_update_charger_charge_settings_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError)):
        result = await api.enode_update_charger_charge_settings(VALID_CHARGER_INPUT)
    assert result is False


# ---------------------------------------------------------------------------
# enode_enable_smart_charging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enode_enable_smart_charging_returns_true_when_user_id_returned():
    api = _make_api()
    mock_response = {"data": {"enodeEnableSmartCharging": {"userId": "user-abc"}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_enable_smart_charging()
    assert result is True


@pytest.mark.asyncio
async def test_enode_enable_smart_charging_returns_false_when_no_user_id():
    api = _make_api()
    mock_response = {"data": {"enodeEnableSmartCharging": {"userId": None}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_enable_smart_charging()
    assert result is False


@pytest.mark.asyncio
async def test_enode_enable_smart_charging_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Not eligible"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_enable_smart_charging()
    assert result is False


@pytest.mark.asyncio
async def test_enode_enable_smart_charging_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError)):
        result = await api.enode_enable_smart_charging()
    assert result is False


@pytest.mark.asyncio
async def test_enode_enable_smart_charging_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.enode_enable_smart_charging()


@pytest.mark.asyncio
async def test_enode_enable_smart_charging_sends_correct_operation_name():
    api = _make_api()
    mock_response = {"data": {"enodeEnableSmartCharging": {"userId": "user-abc"}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.enode_enable_smart_charging()
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "EnodeEnableSmartCharging"


# ---------------------------------------------------------------------------
# enode_disable_smart_charging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enode_disable_smart_charging_returns_true_on_success():
    api = _make_api()
    mock_response = {"data": {"enodeDisableSmartCharging": True}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_disable_smart_charging()
    assert result is True


@pytest.mark.asyncio
async def test_enode_disable_smart_charging_returns_false_when_mutation_returns_false():
    api = _make_api()
    mock_response = {"data": {"enodeDisableSmartCharging": False}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_disable_smart_charging()
    assert result is False


@pytest.mark.asyncio
async def test_enode_disable_smart_charging_returns_false_on_graphql_error():
    api = _make_api()
    mock_response = {"errors": [{"message": "Not authorised"}]}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_disable_smart_charging()
    assert result is False


@pytest.mark.asyncio
async def test_enode_disable_smart_charging_returns_false_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=ConnectionError)):
        result = await api.enode_disable_smart_charging()
    assert result is False


@pytest.mark.asyncio
async def test_enode_disable_smart_charging_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.enode_disable_smart_charging()


@pytest.mark.asyncio
async def test_enode_disable_smart_charging_sends_correct_operation_name():
    api = _make_api()
    mock_response = {"data": {"enodeDisableSmartCharging": True}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.enode_disable_smart_charging()
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "EnodeDisableSmartCharging"


# ---------------------------------------------------------------------------
# Stubs — smoke tests (auth check + operation name + success path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_smart_battery_update_settings_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.smart_battery_update_settings("dev-1", {"batteryMode": "SELF_CONSUMPTION"})


@pytest.mark.asyncio
async def test_smart_battery_update_settings_returns_true_on_success():
    api = _make_api()
    mock_response = {
        "data": {
            "smartBatteryUpdateSettings": {
                "batteryMode": "SELF_CONSUMPTION",
                "createdAt": "2026-01-01T00:00:00Z",
                "imbalanceTradingStrategy": "BALANCED",
                "selfConsumptionTradingThresholdPrice": 0.1,
                "updatedAt": "2026-05-28T12:00:00Z",
            }
        }
    }
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.smart_battery_update_settings("dev-1", {"batteryMode": "SELF_CONSUMPTION"})
    assert result is True


@pytest.mark.asyncio
async def test_smart_battery_update_settings_sends_correct_variables():
    api = _make_api()
    mock_response = {"data": {"smartBatteryUpdateSettings": {}}}
    settings = {"batteryMode": "SELF_CONSUMPTION"}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.smart_battery_update_settings("dev-1", settings)
    called_query = mock_q.call_args[0][0]
    assert called_query.variables["deviceId"] == "dev-1"
    assert called_query.variables["settings"] == settings
    assert called_query.operation_name == "SmartBatteryUpdateSettings"


@pytest.mark.asyncio
async def test_enode_update_all_vehicle_charge_settings_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.enode_update_all_vehicle_charge_settings({"deadline": "2026-05-29T07:00:00Z"})


@pytest.mark.asyncio
async def test_enode_update_all_vehicle_charge_settings_returns_true_on_success():
    api = _make_api()
    mock_response = {"data": {"enodeUpdateAllVehicleChargeSettings": None}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.enode_update_all_vehicle_charge_settings({"deadline": "2026-05-29T07:00:00Z"})
    assert result is True


@pytest.mark.asyncio
async def test_enode_update_all_vehicle_charge_settings_operation_name():
    api = _make_api()
    mock_response = {"data": {"enodeUpdateAllVehicleChargeSettings": None}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.enode_update_all_vehicle_charge_settings({"deadline": "2026-05-29T07:00:00Z"})
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "EnodeUpdateAllVehicleChargeSettings"


@pytest.mark.asyncio
async def test_logout_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.logout("install-123")


@pytest.mark.asyncio
async def test_logout_returns_true_and_clears_auth():
    api = _make_api()
    assert api.is_authenticated
    mock_response = {"data": {"logout": True}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.logout("install-123")
    assert result is True
    assert api._auth is None


@pytest.mark.asyncio
async def test_logout_returns_false_when_mutation_returns_false_and_does_not_clear_auth():
    api = _make_api()
    assert api.is_authenticated
    mock_response = {"data": {"logout": False}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.logout("install-123")
    assert result is False
    assert api.is_authenticated


@pytest.mark.asyncio
async def test_logout_sends_correct_variables():
    api = _make_api()
    mock_response = {"data": {"logout": True}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.logout("install-abc")
    called_query = mock_q.call_args[0][0]
    assert called_query.variables["installationId"] == "install-abc"
    assert called_query.operation_name == "Logout"


@pytest.mark.asyncio
async def test_update_user_settings_raises_when_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.update_user_settings({"language": "nl"})


@pytest.mark.asyncio
async def test_update_user_settings_returns_true_on_success():
    api = _make_api()
    mock_response = {
        "data": {
            "updateUserSettings": {
                "id": "user-1",
                "UserSettings": {
                    "id": "settings-1",
                    "disabledHapticFeedback": False,
                    "language": "nl",
                    "rewardPayoutPreference": "WALLET",
                    "smartPushNotifications": True,
                },
            }
        }
    }
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.update_user_settings({"language": "nl"})
    assert result is True


@pytest.mark.asyncio
async def test_update_user_settings_sends_correct_operation_name():
    api = _make_api()
    mock_response = {"data": {"updateUserSettings": {"id": "u1", "UserSettings": {}}}}
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.update_user_settings({"language": "en"})
    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "UpdateUserSettings"
    assert called_query.variables["input"] == {"language": "en"}
