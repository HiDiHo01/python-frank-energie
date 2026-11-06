"""Regression tests for lossless hardware-inventory error handling."""

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
async def test_explicit_successful_empty_inventory(
    method_name: str, field_name: str, attribute: str
) -> None:
    """A complete and explicitly empty API response is a valid empty inventory."""
    client = FrankEnergie(auth_token="test_token")
    with patch.object(client, "_query", return_value={"data": {field_name: []}}):
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
        "invalid_record",
        "missing_identifier",
        "duplicate_identifier",
    ),
)
async def test_failed_or_incomplete_inventory_cannot_report_device_absence(
    method_name: str, field_name: str, _attribute: str, scenario: str
) -> None:
    """Reject missing, partial, corrupt or failed inventories for all device types."""
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
        "invalid_record": {"data": {field_name: [None]}},
        "missing_identifier": {"data": {field_name: [{"id": ""}]}},
        "duplicate_identifier": {"data": {field_name: [{"id": "device-1"}, {"id": "device-1"}]}},
    }
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value=cases[scenario]),
        pytest.raises(RequestException),
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
async def test_request_errors_keep_original_exception_type(
    method_name: str, error: Exception
) -> None:
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


async def test_invalid_charger_payload_fails_atomically() -> None:
    """An unparseable charger must not silently disappear from inventory."""
    client = FrankEnergie(auth_token="test_token")
    with (
        patch.object(client, "_query", return_value={"data": {"enodeChargers": [{"id": "test-charger"}]}}),
        pytest.raises(RequestException, match="parse enodeChargers"),
    ):
        await client.enode_chargers("test_site", date(2026, 11, 6))
