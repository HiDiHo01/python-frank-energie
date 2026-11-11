"""Tests for Frank Energie Smart PV implementation."""

import json
from unittest.mock import patch

import aiohttp
import pytest
from syrupy.assertion import SnapshotAssertion

from python_frank_energie import FrankEnergie, SmartFeedInNotEnabledException
from python_frank_energie.domain import SmartPvSteeringStatus
from python_frank_energie.exceptions import RequestException
from python_frank_energie.models import SmartPvSystems

from . import load_fixtures

SIMPLE_DATA_URL = "frank-graphql-prod.graphcdn.app"


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_smart_pv_systems(aresponses, snapshot: SnapshotAssertion):
    """Test smart_pv_systems query."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("smart_pv_systems.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        pv_systems = await api.smart_pv_systems()
        await api.close()

    assert pv_systems is not None
    assert pv_systems == snapshot


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_smart_pv_system_summary(aresponses, snapshot: SnapshotAssertion):
    """Test smart_pv_system_summary query."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("smart_pv_system_summary.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        summary = await api.smart_pv_system_summary("pv-123")
        await api.close()

    assert summary is not None
    assert summary == snapshot


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_user_smart_feed_in(aresponses, snapshot: SnapshotAssertion):
    """Test user_smart_feed_in query."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("user_smart_feed_in.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        feed_in = await api.user_smart_feed_in()
        await api.close()

    assert feed_in is not None
    assert feed_in == snapshot


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_enode_vehicles_parsing(aresponses, snapshot: SnapshotAssertion):
    """Test enode_vehicles parsing method."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("enode_vehicles.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        vehicles = await api.enode_vehicles()
        await api.close()

    assert vehicles is not None
    assert vehicles == snapshot


def _sample_pv_record() -> dict[str, object]:
    """Return an isolated, synthetic PV system with all queried fields."""
    response = json.loads(load_fixtures("smart_pv_systems.json"))
    return response["data"]["smartPvSystems"][0]


@pytest.mark.parametrize("include_empty_errors", (False, True))
def test_pv_explicit_empty_inventory(include_empty_errors: bool) -> None:
    """Only a successful explicit empty collection establishes PV absence."""
    response: dict[str, object] = {"data": {"smartPvSystems": []}}
    if include_empty_errors:
        response["errors"] = []
    assert SmartPvSystems.from_dict(response).systems == []


@pytest.mark.parametrize(
    "response",
    (
        None,
        {},
        {"data": None},
        {"data": []},
        {"data": {}},
        {"data": {"smartPvSystems": None}},
        {"data": {"smartPvSystems": {}}},
        {"data": {"smartPvSystems": "[]"}},
        {"data": {"smartPvSystems": [None]}},
        {"data": {"smartPvSystems": ["invalid"]}},
        {"data": {"smartPvSystems": []}, "errors": None},
        {"data": {"smartPvSystems": []}, "errors": {}},
        {"data": {"smartPvSystems": []}, "errors": ""},
        {"data": {"smartPvSystems": []}, "errors": [{"message": "Upstream failed"}]},
    ),
)
def test_pv_invalid_response_never_counts_as_empty(response: dict[str, object] | None) -> None:
    """Reject failed or malformed GraphQL responses before device validation."""
    with pytest.raises(RequestException):
        SmartPvSystems.from_dict(response)


@pytest.mark.parametrize("bad_id", (None, 1, "", " ", "pv-123 ", " pv-123"))
def test_pv_invalid_identifiers_rejected(bad_id: object) -> None:
    """Reject non-string, blank and whitespace-padded PV IDs."""
    system = _sample_pv_record()
    system["id"] = bad_id
    with pytest.raises(RequestException, match="inventory ID"):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


def test_pv_duplicate_identifiers_rejected() -> None:
    """Reject duplicate PV systems rather than returning partial inventory."""
    system = _sample_pv_record()
    with pytest.raises(RequestException, match="Duplicate smartPvSystems inventory ID"):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system, dict(system)]}})


@pytest.mark.parametrize(
    "missing_field",
    (
        "id",
        "brand",
        "connectionEAN",
        "createdAt",
        "deletedAt",
        "displayName",
        "externalReference",
        "inverterSerialNumbers",
        "model",
        "onboardingStatus",
        "provider",
        "steeringStatus",
        "updatedAt",
        "SmartPvSystemPanelGroups",
    ),
)
def test_pv_missing_queried_field_is_invalid(missing_field: str) -> None:
    """Reject incomplete records even when the missing field is nullable."""
    system = _sample_pv_record()
    system.pop(missing_field)
    with pytest.raises(RequestException, match="Incomplete smartPvSystems"):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


@pytest.mark.parametrize("panel_groups", (None, {}, [None], [{}]))
def test_pv_invalid_panel_groups_rejected(panel_groups: object) -> None:
    """An invalid nested panel group must not be silently discarded."""
    system = _sample_pv_record()
    system["SmartPvSystemPanelGroups"] = panel_groups
    with pytest.raises(RequestException, match="SmartPvSystemPanelGroups"):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


def test_pv_duplicate_panel_group_identifiers_rejected() -> None:
    """Reject duplicate nested IDs rather than returning partial panel data."""
    system = _sample_pv_record()
    group = {
        "id": "panel-1",
        "position": 1,
        "azimuth": 180,
        "tilt": 15,
        "capacityKwp": 3.06,
        "annualKwh": 2600,
        "panelCount": 7,
        "installationDate": None,
    }
    system["SmartPvSystemPanelGroups"] = [group, dict(group)]
    with pytest.raises(RequestException, match="Duplicate SmartPvSystemPanelGroups"):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


@pytest.mark.parametrize("serial_numbers", ({"invalid": "shape"}, ["good", None]))
def test_pv_invalid_serial_numbers_rejected(serial_numbers: object) -> None:
    """Reject incorrectly typed nested serial-number values."""
    system = _sample_pv_record()
    system["inverterSerialNumbers"] = serial_numbers
    with pytest.raises(RequestException, match="inverter serial numbers"):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


def test_pv_nullable_serial_numbers_remain_supported() -> None:
    """Keep the previously supported explicitly null inverter-serial list."""
    system = _sample_pv_record()
    system["inverterSerialNumbers"] = None
    inventory = SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})
    assert len(inventory.systems) == 1
    assert inventory.systems[0].inverter_serial_numbers == []


def test_pv_unknown_steering_status_retains_fallback() -> None:
    """Preserve the library's UNKNOWN fallback for new provider status values."""
    system = _sample_pv_record()
    system["steeringStatus"] = "NEW_PROVIDER_STATUS"
    inventory = SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})
    assert inventory.systems[0].steering_status is SmartPvSteeringStatus.UNKNOWN


@pytest.mark.asyncio
async def test_pv_public_api_accepts_explicit_empty_inventory() -> None:
    """Check a successfully fetched empty inventory via the public API."""
    api = FrankEnergie(auth_token="test_token")  # noqa: S106
    with patch.object(api, "_query", return_value={"data": {"smartPvSystems": []}}):
        assert (await api.smart_pv_systems()).systems == []


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_pv_service_disabled_graphql_response_is_not_empty(aresponses, caplog) -> None:
    """Verify the observed HTTP GraphQL error using the real request path."""
    marker = "private-fixture-sentinel"
    response = {
        "data": None,
        "errors": [
            {
                "message": "user-error:smart-feed-in-not-enabled",
                "locations": [{"line": 2, "column": 3}],
                "path": ["smartPvSystems"],
                "extensions": {"sensitive": marker},
            }
        ],
    }
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=json.dumps(response),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        with pytest.raises(SmartFeedInNotEnabledException, match="Smart Feed-In"):
            await api.smart_pv_systems()
    assert marker not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    (
        {
            "data": None,
            "errors": [{"message": "user-error:smart-feed-in-not-enabled", "path": ["other"]}],
        },
        {
            "data": {"smartPvSystems": []},
            "errors": [{"message": "user-error:smart-feed-in-not-enabled", "path": ["smartPvSystems"]}],
        },
        {
            "data": None,
            "errors": [
                {"message": "user-error:smart-feed-in-not-enabled", "path": ["smartPvSystems"]},
                {"message": "Other error"},
            ],
        },
    ),
)
async def test_pv_other_graphql_errors_are_not_service_disabled(response: dict[str, object]) -> None:
    """Reject mixed, partial and wrong-path GraphQL errors without reclassifying them."""
    api = FrankEnergie(auth_token="test_token")  # noqa: S106
    with (
        patch.object(api, "_query", return_value=response),
        pytest.raises(RequestException) as caught,
    ):
        await api.smart_pv_systems()
    assert not isinstance(caught.value, SmartFeedInNotEnabledException)
