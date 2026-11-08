"""Regression tests for lossless hardware-inventory error handling."""

import json
from datetime import date
from unittest.mock import patch

import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import (
    AuthException,
    NetworkError,
    RateLimitException,
    RequestException,
    SmartChargingNotEnabledException,
    SmartTradingNotEnabledException,
)

from . import load_fixtures

pytestmark = pytest.mark.asyncio

_INVENTORY_METHODS = (
    ("enode_chargers", "enodeChargers", "chargers"),
    ("enode_vehicles", "enodeVehicles", "vehicles"),
    ("smart_batteries", "smartBatteries", "batteries"),
)


async def _fetch_inventory(client: FrankEnergie, method_name: str) -> object:
    """Fetch a mocked inventory via its public asynchronous API."""
    if method_name == "enode_chargers":
        return await client.enode_chargers("test_site", date(2026, 11, 6))
    if method_name == "enode_vehicles":
        return await client.enode_vehicles()
    if method_name == "smart_batteries":
        return await client.smart_batteries()
    raise ValueError(f"Unknown inventory method: {method_name}")


@pytest.mark.parametrize(("method_name", "field_name", "attribute"), _INVENTORY_METHODS)
@pytest.mark.parametrize("include_empty_errors", (False, True))
async def test_explicit_successful_empty_inventory(
    method_name: str, field_name: str, attribute: str, include_empty_errors: bool
) -> None:
    """A complete and explicitly empty API response is a valid empty inventory."""
    response: dict[str, object] = {"data": {field_name: []}}
    if include_empty_errors:
        response["errors"] = []
    client = FrankEnergie(auth_token="test_token")
    with patch.object(client, "_query", return_value=response):
        inventory = await _fetch_inventory(client, method_name)
    assert getattr(inventory, attribute) == []


@pytest.mark.parametrize(("method_name", "field_name", "_attribute"), _INVENTORY_METHODS)
@pytest.mark.parametrize(
    "scenario",
    (
        "no_response",
        "no_data",
        "missing_collection",
        "null_collection",
        "invalid_collection",
        "graphql_error",
        "partial_graphql_error",
        "invalid_errors_empty_dict",
        "invalid_errors_empty_string",
        "invalid_errors_null",
        "invalid_errors_string",
        "invalid_record",
        "missing_identifier",
        "duplicate_identifier",
    ),
)
async def test_failed_or_incomplete_inventory_cannot_report_device_absence(
    method_name: str, field_name: str, _attribute: str, scenario: str
) -> None:
    """Reject missing, partial, corrupt or failed inventories for all device types."""
    duplicate_record: dict[str, object] = {
        "id": "device-1",
        "canSmartCharge": True,
        "chargeSettings": {"isSmartChargingEnabled": True},
        "chargeState": {"isCharging": False, "isPluggedIn": False},
        "information": {},
        "interventions": [],
        "isReachable": True,
        "lastSeen": None,
    }
    if field_name == "smartBatteries":
        duplicate_record.update(
            {
                "brand": None,
                "capacity": None,
                "createdAt": None,
                "externalReference": None,
                "maxChargePower": None,
                "maxDischargePower": None,
                "provider": None,
                "updatedAt": None,
            }
        )
    cases: dict[str, object] = {
        "no_response": None,
        "no_data": {"data": None},
        "missing_collection": {"data": {}},
        "null_collection": {"data": {field_name: None}},
        "invalid_collection": {"data": {field_name: {}}},
        "graphql_error": {"errors": [{"message": "Temporary upstream error"}]},
        "partial_graphql_error": {
            "data": {field_name: []},
            "errors": [{"message": "Partial upstream error"}],
        },
        "invalid_errors_empty_dict": {"data": {field_name: []}, "errors": {}},
        "invalid_errors_empty_string": {"data": {field_name: []}, "errors": ""},
        "invalid_errors_null": {"data": {field_name: []}, "errors": None},
        "invalid_errors_string": {"data": {field_name: []}, "errors": "upstream error"},
        "invalid_record": {"data": {field_name: [None]}},
        "missing_identifier": {"data": {field_name: [{"id": ""}]}},
        "duplicate_identifier": {"data": {field_name: [duplicate_record, {**duplicate_record}] }},
    }
    client = FrankEnergie(auth_token="test_token")
    expected_message = "duplicate device ID" if scenario == "duplicate_identifier" else None
    with (
        patch.object(client, "_query", return_value=cases[scenario]),
        pytest.raises(RequestException, match=expected_message),
    ):
        await _fetch_inventory(client, method_name)


@pytest.mark.parametrize(
    ("method_name", "error"),
    (
        ("enode_chargers", SmartChargingNotEnabledException("Not enabled")),
        ("enode_vehicles", SmartChargingNotEnabledException("Not enabled")),
        ("smart_batteries", SmartTradingNotEnabledException("Not enabled")),
        ("enode_chargers", AuthException("Unauthorised")),
        ("enode_vehicles", NetworkError("Connection interrupted")),
        ("smart_batteries", RateLimitException("SmartBatteries", retry_after=30)),
    ),
)
async def test_request_errors_keep_original_exception_type(method_name: str, error: Exception) -> None:
    """Preserve authentication, feature, throttling and network exceptions."""
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", side_effect=error),
        pytest.raises(type(error)) as caught,
    ):
        await _fetch_inventory(client, method_name)
    assert caught.value is error


@pytest.mark.parametrize(("method_name", "_field_name", "_attribute"), _INVENTORY_METHODS)
async def test_unexpected_transport_error_is_not_an_empty_inventory(
    method_name: str, _field_name: str, _attribute: str
) -> None:
    """Wrap unexpected transport errors while retaining their original cause."""
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", side_effect=TimeoutError("Timed out")),
        pytest.raises(RequestException) as caught,
    ):
        await _fetch_inventory(client, method_name)
    assert isinstance(caught.value.__cause__, TimeoutError)


def _fixture_inventory_record(filename: str, field_name: str) -> dict[str, object]:
    """Return a sanitized device record from an existing API fixture."""
    response = json.loads(load_fixtures(filename))
    return response["data"][field_name][0]


@pytest.mark.parametrize(
    "missing_field",
    (
        "brand",
        "capacity",
        "createdAt",
        "externalReference",
        "maxChargePower",
        "maxDischargePower",
        "provider",
        "updatedAt",
    ),
)
async def test_missing_battery_field_rejects_inventory(missing_field: str) -> None:
    """All queried battery fields must be present, including nullable fields."""
    battery = _fixture_inventory_record("smart_batteries.json", "smartBatteries")
    del battery[missing_field]
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {"smartBatteries": [battery]}}),
        pytest.raises(RequestException, match="Incomplete smartBatteries"),
    ):
        await client.smart_batteries()


async def test_nullable_battery_fields_are_supported() -> None:
    """An explicitly returned null battery field is not a missing field."""
    battery = _fixture_inventory_record("smart_batteries.json", "smartBatteries")
    for field_name in (
        "brand",
        "capacity",
        "createdAt",
        "externalReference",
        "maxChargePower",
        "maxDischargePower",
        "provider",
        "updatedAt",
    ):
        battery[field_name] = None
    client = FrankEnergie(auth_token="test_token")
    with patch.object(client, "_query", return_value={"data": {"smartBatteries": [battery]}}):
        inventory = await client.smart_batteries()
    assert len(inventory.batteries) == 1
    assert inventory.batteries[0].brand is None
    assert inventory.batteries[0].capacity is None


@pytest.mark.parametrize(
    ("method_name", "field_name"),
    (("enode_chargers", "enodeChargers"), ("enode_vehicles", "enodeVehicles")),
)
@pytest.mark.parametrize(
    "interventions",
    (
        None,
        "not-a-list",
        {},
        [{}],
        [None],
        ["invalid-record"],
        [{"title": "Incomplete"}],
        [{"title": None, "description": "Malformed"}],
        [{"title": 42, "description": "Malformed"}],
        [{"title": "Malformed", "description": None}],
        [{"title": "Malformed", "description": 42}],
    ),
)
async def test_malformed_interventions_reject_inventory(
    method_name: str, field_name: str, interventions: object
) -> None:
    """Reject malformed interventions with an inventory-specific error."""
    vehicle = _fixture_inventory_record("enode_vehicles.json", "enodeVehicles")
    vehicle["interventions"] = interventions
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {field_name: [vehicle]}}),
        pytest.raises(RequestException, match=f"Invalid {field_name} inventory interventions"),
    ):
        await _fetch_inventory(client, method_name)


async def test_nullable_vehicle_state_fields_are_supported() -> None:
    """Retain supported nullable vehicle deadlines, charge state and last-seen time."""
    vehicle = _fixture_inventory_record("enode_vehicles.json", "enodeVehicles")
    vehicle["lastSeen"] = None
    vehicle["chargeSettings"]["calculatedDeadline"] = None
    vehicle["chargeState"]["batteryLevel"] = None
    client = FrankEnergie(auth_token="test_token")
    with patch.object(client, "_query", return_value={"data": {"enodeVehicles": [vehicle]}}):
        inventory = await client.enode_vehicles()
    assert len(inventory.vehicles) == 1
    assert inventory.vehicles[0].last_seen is None
    assert inventory.vehicles[0].charge_settings.calculated_deadline is None
    assert inventory.vehicles[0].charge_state.battery_level is None


@pytest.mark.parametrize(
    ("method_name", "field_name"),
    (("enode_chargers", "enodeChargers"), ("enode_vehicles", "enodeVehicles")),
)
async def test_missing_last_seen_rejects_inventory(method_name: str, field_name: str) -> None:
    """Reject a missing lastSeen instead of treating it as an explicit null."""
    device = _fixture_inventory_record("enode_vehicles.json", "enodeVehicles")
    del device["lastSeen"]
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {field_name: [device]}}),
        pytest.raises(RequestException, match=f"Incomplete {field_name}"),
    ):
        await _fetch_inventory(client, method_name)


@pytest.mark.parametrize(("method_name", "field_name", "attribute"), _INVENTORY_METHODS[:2])
async def test_nullable_last_seen_is_valid(method_name: str, field_name: str, attribute: str) -> None:
    """Accept an explicit null lastSeen for both chargers and vehicles."""
    device = _fixture_inventory_record("enode_vehicles.json", "enodeVehicles")
    device["lastSeen"] = None
    client = FrankEnergie(auth_token="test_token")
    with patch.object(client, "_query", return_value={"data": {field_name: [device]}}):
        inventory = await _fetch_inventory(client, method_name)
    devices = getattr(inventory, attribute)
    assert len(devices) == 1
    assert devices[0].last_seen is None



@pytest.mark.parametrize(
    ("method_name", "field_name"),
    (("enode_chargers", "enodeChargers"), ("enode_vehicles", "enodeVehicles")),
)
@pytest.mark.parametrize("last_seen", (42, {}, "invalid", "2026-11-06T10:00:00"))
async def test_malformed_last_seen_rejects_inventory(
    method_name: str, field_name: str, last_seen: object
) -> None:
    """Reject malformed or timezone-naive lastSeen values for Enode devices."""
    device = _fixture_inventory_record("enode_vehicles.json", "enodeVehicles")
    device["lastSeen"] = last_seen
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {field_name: [device]}}),
        pytest.raises(RequestException, match="lastSeen"),
    ):
        await _fetch_inventory(client, method_name)


@pytest.mark.parametrize(
    ("method_name", "field_name"),
    (("enode_chargers", "enodeChargers"), ("enode_vehicles", "enodeVehicles")),
)
@pytest.mark.parametrize(
    ("container_name", "boolean_field"),
    (
        ("chargeSettings", "isSmartChargingEnabled"),
        ("chargeSettings", "isSolarChargingEnabled"),
        ("chargeState", "isCharging"),
        ("chargeState", "isPluggedIn"),
        ("chargeState", "isFullyCharged"),
    ),
)
@pytest.mark.parametrize("invalid_value", ("false", 0, 1))
async def test_invalid_nested_boolean_rejects_inventory(
    method_name: str,
    field_name: str,
    container_name: str,
    boolean_field: str,
    invalid_value: object,
) -> None:
    """Reject truthy non-booleans before model parsing can coerce them."""
    device = _fixture_inventory_record("enode_vehicles.json", "enodeVehicles")
    nested_data = device[container_name]
    nested_data[boolean_field] = invalid_value
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {field_name: [device]}}),
        pytest.raises(RequestException, match="inventory"),
    ):
        await _fetch_inventory(client, method_name)


@pytest.mark.parametrize("field_name", ("brand", "externalReference", "provider"))
@pytest.mark.parametrize("invalid_value", (False, 42, [], {}))
async def test_malformed_battery_text_metadata_rejects_inventory(field_name: str, invalid_value: object) -> None:
    """Reject wrong text types rather than silently dropping battery metadata."""
    battery = _fixture_inventory_record("smart_batteries.json", "smartBatteries")
    battery[field_name] = invalid_value
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {"smartBatteries": [battery]}}),
        pytest.raises(RequestException, match=field_name),
    ):
        await client.smart_batteries()


@pytest.mark.parametrize("field_name", ("createdAt", "updatedAt"))
@pytest.mark.parametrize(
    "invalid_value",
    (42, [], {}, "", "invalid-date", "2026-11-06", "2026-11-06T10:00:00"),
)
async def test_malformed_battery_timestamp_rejects_inventory(field_name: str, invalid_value: object) -> None:
    """Reject invalid and timezone-naive battery timestamps."""
    battery = _fixture_inventory_record("smart_batteries.json", "smartBatteries")
    battery[field_name] = invalid_value
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {"smartBatteries": [battery]}}),
        pytest.raises(RequestException, match=field_name),
    ):
        await client.smart_batteries()


@pytest.mark.parametrize("iso_datetime", ("2024-04-30T13:33:42Z", "2024-04-30T15:33:42+02:00"))
async def test_valid_battery_timestamp_metadata_is_preserved(iso_datetime: str) -> None:
    """Preserve the instant represented by valid timezone-aware battery timestamps."""
    battery = _fixture_inventory_record("smart_batteries.json", "smartBatteries")
    battery["createdAt"] = iso_datetime
    battery["updatedAt"] = iso_datetime
    client = FrankEnergie(auth_token="test_token")
    with patch.object(client, "_query", return_value={"data": {"smartBatteries": [battery]}}):
        inventory = await client.smart_batteries()
    assert inventory.batteries[0].created_at is not None
    assert inventory.batteries[0].updated_at is not None
    assert inventory.batteries[0].created_at.isoformat() == "2024-04-30T13:33:42+00:00"
    assert inventory.batteries[0].updated_at.isoformat() == "2024-04-30T13:33:42+00:00"


@pytest.mark.parametrize("information", (None, [], "invalid", 42))
async def test_malformed_charger_information_rejects_inventory(information: object) -> None:
    """Reject malformed information even when the other charger fields are present."""
    charger = {
        "id": "test-charger",
        "canSmartCharge": True,
        "chargeSettings": {},
        "chargeState": {},
        "information": information,
        "interventions": [],
        "isReachable": True,
        "lastSeen": None,
    }
    client = FrankEnergie(auth_token="test_token")
    start_date = date(2026, 11, 6)
    with (
        patch.object(client, "_query", return_value={"data": {"enodeChargers": [charger]}}),
        pytest.raises(RequestException, match="information"),
    ):
        await client.enode_chargers("test_site", start_date)


@pytest.mark.parametrize("field_name", ("capacity", "maxChargePower", "maxDischargePower"))
@pytest.mark.parametrize("value", ("invalid", "", [], {}, True, float("nan"), float("inf"), "-Infinity"))
async def test_malformed_battery_number_rejects_inventory(field_name: str, value: object) -> None:
    """Invalid numeric data must not be silently converted to a nullable value."""
    battery = _fixture_inventory_record("smart_batteries.json", "smartBatteries")
    invalid_battery = {**battery, "id": "invalid-battery", field_name: value}
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {"smartBatteries": [battery, invalid_battery]}}),
        pytest.raises(RequestException, match=field_name),
    ):
        await client.smart_batteries()


@pytest.mark.parametrize("value", (0, 10, 10.5, "10.5"))
async def test_valid_battery_numbers_are_supported(value: object) -> None:
    """Retain the model's existing support for numbers and numeric strings."""
    battery = _fixture_inventory_record("smart_batteries.json", "smartBatteries")
    for field_name in ("capacity", "maxChargePower", "maxDischargePower"):
        battery[field_name] = value
    client = FrankEnergie(auth_token="test_token")
    with patch.object(client, "_query", return_value={"data": {"smartBatteries": [battery]}}):
        inventory = await client.smart_batteries()
    assert inventory.batteries[0].capacity == float(value)
    assert inventory.batteries[0].max_charge_power == float(value)
    assert inventory.batteries[0].max_discharge_power == float(value)


@pytest.mark.parametrize("interventions", ([], [{"title": "Test", "description": "Test intervention"}]))
async def test_invalid_charger_payload_fails_atomically(interventions: list[dict[str, str]]) -> None:
    """A valid charger followed by an unparseable one must fail the whole request."""
    valid_charger = {
        "id": "valid-charger",
        "canSmartCharge": True,
        "chargeSettings": {
            "hourFriday": 420,
            "hourMonday": 420,
            "hourSaturday": 420,
            "hourSunday": 420,
            "hourThursday": 420,
            "hourTuesday": 420,
            "hourWednesday": 420,
            "id": "valid-settings",
            "isSmartChargingEnabled": True,
            "maxChargeLimit": 80,
            "minChargeLimit": 20,
        },
        "chargeState": {"isCharging": False, "isPluggedIn": False},
        "information": {"brand": "Test", "model": "Charger", "year": None},
        "interventions": interventions,
        "isReachable": True,
        "lastSeen": None,
    }
    invalid_charger = {**valid_charger, "id": "invalid-charger", "chargeSettings": {"id": "invalid-settings"}}
    client = FrankEnergie(auth_token="test_token")
    start_date = date(2026, 11, 6)
    with patch.object(client, "_query", return_value={"data": {"enodeChargers": [valid_charger]}}):
        inventory = await client.enode_chargers("test_site", start_date)
    assert [charger.id for charger in inventory.chargers] == ["valid-charger"]
    assert [
        {"title": item.title, "description": item.description} for item in inventory.chargers[0].interventions
    ] == interventions
    with (
        patch.object(
            client,
            "_query",
            return_value={"data": {"enodeChargers": [valid_charger, invalid_charger]}},
        ),
        pytest.raises(RequestException, match="parse enodeChargers"),
    ):
        await client.enode_chargers("test_site", start_date)
