"""Tests for Frank Energie Smart PV implementation."""

import json
import logging
from datetime import UTC, datetime
from unittest.mock import patch

import aiohttp
import pytest
from syrupy.assertion import SnapshotAssertion

from python_frank_energie import FrankEnergie, SmartFeedInNotEnabledException
from python_frank_energie.domain import SmartPvSteeringStatus
from python_frank_energie.exceptions import RequestException
from python_frank_energie.models import SmartPvSystems, SmartPvSystemSummary

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


def _sample_pv_panel_group() -> dict[str, object]:
    """Build a complete, synthetic panel group with valid optional values."""
    return {
        "id": "panel-1",
        "position": 1,
        "azimuth": 180,
        "tilt": 15,
        "capacityKwp": 3.06,
        "annualKwh": 2600,
        "panelCount": 7,
        "installationDate": "2026-05-28T10:00:00Z",
    }


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("position", "bad"),
        ("azimuth", True),
        ("tilt", 1.5),
        ("capacityKwp", "invalid"),
        ("capacityKwp", True),
        ("capacityKwp", "NaN"),
        ("annualKwh", "invalid"),
        ("annualKwh", 2.5),
        ("panelCount", "invalid"),
        ("panelCount", 1.5),
        ("panelCount", float("inf")),
        ("installationDate", 42),
        ("installationDate", ""),
        ("installationDate", "not-a-date"),
        ("installationDate", "2026-02-30"),
    ),
)
def test_pv_malformed_panel_group_values_rejected(field_name: str, invalid_value: object) -> None:
    """Reject malformed non-null panel values instead of silently returning None."""
    system = _sample_pv_record()
    group = _sample_pv_panel_group()
    group[field_name] = invalid_value
    system["SmartPvSystemPanelGroups"] = [group]
    with pytest.raises(RequestException, match=field_name):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


@pytest.mark.parametrize(
    "field_name",
    ("position", "azimuth", "tilt", "capacityKwp", "annualKwh", "panelCount", "installationDate"),
)
def test_pv_nullable_panel_group_fields_remain_valid(field_name: str) -> None:
    """Preserve supported null values for optional panel attributes."""
    system = _sample_pv_record()
    group = _sample_pv_panel_group()
    group[field_name] = None
    system["SmartPvSystemPanelGroups"] = [group]
    inventory = SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})
    assert len(inventory.systems[0].panel_groups) == 1


def test_pv_valid_panel_group_numeric_strings_remain_supported() -> None:
    """Keep numeric-string parsing that is already supported by the PV models."""
    system = _sample_pv_record()
    group = _sample_pv_panel_group()
    group.update(
        position="1",
        azimuth="180",
        tilt="15",
        capacityKwp="3.06",
        annualKwh="2600",
        panelCount="7",
    )
    system["SmartPvSystemPanelGroups"] = [group]
    inventory = SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})
    parsed = inventory.systems[0].panel_groups[0]
    assert parsed.panel_count == 7
    assert parsed.annual_kwh == 2600
    assert parsed.capacity_kwp == 3.06


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("deletedAt", 123),
        ("deletedAt", ""),
        ("deletedAt", "invalid-date"),
        ("deletedAt", "2026-02-30"),
        ("connectionEAN", None),
        ("connectionEAN", 123),
        ("brand", None),
        ("externalReference", None),
        ("provider", None),
        ("onboardingStatus", None),
        ("steeringStatus", None),
        ("displayName", 123),
        ("model", {}),
    ),
)
def test_pv_malformed_system_metadata_rejected(field_name: str, invalid_value: object) -> None:
    """Reject malformed required and optional metadata before model coercions."""
    system = _sample_pv_record()
    system[field_name] = invalid_value
    with pytest.raises(RequestException, match=field_name):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


def test_pv_valid_deletion_date_and_null_ean_guards() -> None:
    """Permit valid deletedAt while retaining the existing non-null string EAN model."""
    system = _sample_pv_record()
    system["deletedAt"] = "2026-05-29T10:00:00Z"
    inventory = SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})
    assert inventory.systems[0].deleted_at is not None
    assert inventory.systems[0].connection_ean == system["connectionEAN"]


def test_pv_invalid_metadata_is_not_reflected_in_exception() -> None:
    """Avoid leaking provider-supplied metadata in validation messages."""
    system = _sample_pv_record()
    marker = "private-fictitious-data"
    system["deletedAt"] = marker
    with pytest.raises(RequestException, match="deletedAt") as caught:
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})
    assert marker not in str(caught.value)


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
        with (
            caplog.at_level(logging.DEBUG, logger="python_frank_energie"),
            pytest.raises(SmartFeedInNotEnabledException, match="Smart Feed-In"),
        ):
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


@pytest.mark.parametrize(
    "missing_field",
    ("id", "position", "azimuth", "tilt", "capacityKwp", "annualKwh", "panelCount", "installationDate"),
)
def test_pv_missing_queried_panel_group_field_rejected(missing_field: str) -> None:
    """Require every selected panel-group field, even when its value may be null."""
    system = _sample_pv_record()
    group = _sample_pv_panel_group()
    group.pop(missing_field)
    system["SmartPvSystemPanelGroups"] = [group]
    with pytest.raises(RequestException, match="SmartPvSystemPanelGroups"):
        SmartPvSystems.from_dict({"data": {"smartPvSystems": [system]}})


def test_pv_multiple_systems_preserve_individual_panel_groups() -> None:
    """Preserve distinct system identities and their independent nested groups."""
    first = _sample_pv_record()
    second = _sample_pv_record()
    second["id"] = "pv-456"
    second["externalReference"] = "ext-456"
    second["connectionEAN"] = "000000000000000000"
    second["SmartPvSystemPanelGroups"] = []
    second["steeringStatus"] = "INACTIVE"
    inventory = SmartPvSystems.from_dict({"data": {"smartPvSystems": [first, second]}})
    assert [system.id for system in inventory.systems] == ["pv-123", "pv-456"]
    assert inventory.systems[0].panel_groups[0].id == "panel-1"
    assert inventory.systems[0].panel_groups[0].panel_count == 7
    assert inventory.systems[0].panel_groups[0].installation_date is not None
    assert inventory.systems[1].panel_groups == []
    assert inventory.systems[1].steering_status is SmartPvSteeringStatus.INACTIVE


def _sample_pv_summary() -> dict[str, object]:
    """Return a complete synthetic summary with every selected field."""
    return json.loads(load_fixtures("smart_pv_system_summary.json"))["data"]["smartPvSystemSummary"]


@pytest.mark.parametrize(
    "missing_field",
    ("operationalStatus", "operationalStatusTimestamp", "steeringStatus", "totalBonus", "totalResult"),
)
def test_pv_summary_missing_queried_fields_rejected(missing_field: str) -> None:
    """Do not silently turn omitted GraphQL summary fields into null values."""
    summary = _sample_pv_summary()
    summary.pop(missing_field)
    with pytest.raises(RequestException, match="smartPvSystemSummary"):
        SmartPvSystemSummary.from_dict({"data": {"smartPvSystemSummary": summary}})


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("operationalStatus", None),
        ("operationalStatus", 1),
        ("steeringStatus", ""),
        ("steeringStatus", False),
        ("operationalStatusTimestamp", 42),
        ("operationalStatusTimestamp", ""),
        ("operationalStatusTimestamp", "not-a-date"),
        ("totalBonus", True),
        ("totalBonus", "NaN"),
        ("totalResult", "not-a-number"),
        ("totalResult", float("inf")),
    ),
)
def test_pv_summary_malformed_values_rejected(field_name: str, invalid_value: object) -> None:
    """Reject malformed non-null values instead of silently reporting missing data."""
    summary = _sample_pv_summary()
    summary[field_name] = invalid_value
    with pytest.raises(RequestException, match=field_name):
        SmartPvSystemSummary.from_dict({"data": {"smartPvSystemSummary": summary}})


@pytest.mark.parametrize("nullable_field", ("operationalStatusTimestamp", "totalBonus", "totalResult"))
def test_pv_summary_explicit_null_values_remain_supported(nullable_field: str) -> None:
    """Retain existing nullable summary fields when the provider supplies null."""
    summary = _sample_pv_summary()
    summary[nullable_field] = None
    result = SmartPvSystemSummary.from_dict({"data": {"smartPvSystemSummary": summary}})
    attribute_name = {
        "operationalStatusTimestamp": "operational_status_timestamp",
        "totalBonus": "total_bonus",
        "totalResult": "total_result",
    }[nullable_field]
    assert getattr(result, attribute_name) is None


@pytest.mark.parametrize(
    "invalid_response",
    (
        None,
        {},
        {"data": None},
        {"data": {"smartPvSystemSummary": None}},
        {"data": {"smartPvSystemSummary": []}},
        {"data": {"smartPvSystemSummary": {}}, "errors": [{"message": "unavailable"}]},
    ),
)
def test_pv_summary_invalid_envelopes_rejected(invalid_response: object) -> None:
    """Require a complete successful summary response, not an arbitrary mapping."""
    with pytest.raises(RequestException):
        SmartPvSystemSummary.from_dict(invalid_response)


def test_pv_summary_preserves_utc_offset_and_direct_payload() -> None:
    """Convert offset-aware timestamps into UTC and retain direct-payload parsing."""
    summary = _sample_pv_summary()
    summary["operationalStatusTimestamp"] = "2026-05-28T16:00:00+02:00"
    parsed = SmartPvSystemSummary.from_dict(summary)
    assert parsed.operational_status_timestamp == datetime(2026, 5, 28, 14, tzinfo=UTC)
    assert parsed.total_result == 8.9
