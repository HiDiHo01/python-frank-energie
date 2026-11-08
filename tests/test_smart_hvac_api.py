"""Regression tests for site activation and independent Smart HVAC device endpoints."""

import logging
from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, patch

import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthRequiredException, RequestException
from python_frank_energie.models import Me, SmartHvac


@pytest.fixture
def api() -> FrankEnergie:
    """Create an authenticated client without contacting upstream services."""
    return FrankEnergie(auth_token="synthetic-test-token", refresh_token="synthetic-test-token")  # noqa: S106


def _feature_response(
    *,
    activated: bool | None = True,
    available_on_site: bool | None = False,
    accepted_terms: bool | None = True,
) -> dict[str, object]:
    """Construct the sanitized status shape observed in app traffic."""
    return {
        "data": {
            "userSmartHvac": {
                "hasAcceptedTerms": accepted_terms,
                "isActivated": activated,
                "isAvailableInCountry": True,
                "isAvailableOnSite": available_on_site,
                "userCreatedAt": None,
                "userId": None,
            }
        }
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("activated", "available_on_site", "accepted_terms"),
    [(True, False, True), (False, True, False), (None, None, None)],
)
async def test_site_status_preserves_three_way_flags(
    api: FrankEnergie,
    activated: bool | None,
    available_on_site: bool | None,
    accepted_terms: bool | None,
) -> None:
    """Expose activation and site availability separately, preserving null."""
    response = _feature_response(
        activated=activated,
        available_on_site=available_on_site,
        accepted_terms=accepted_terms,
    )
    with patch.object(api, "_query", new=AsyncMock(return_value=response)) as request:
        result = await api.smart_hvac_status("1234AB 10")

    assert result is not None
    assert result.isActivated is activated
    assert result.is_available_on_site is available_on_site
    assert result.has_accepted_terms is accepted_terms
    assert result.userCreatedAt is None
    assert result.userId is None
    operation = request.call_args.args[0]
    assert operation.operation_name == "UserSmartHvac"
    assert operation.variables == {"siteReference": "1234AB 10"}
    assert "userSmartHvac(siteReference: $siteReference)" in operation.query
    for field_name in (
        "hasAcceptedTerms",
        "isActivated",
        "isAvailableInCountry",
        "isAvailableOnSite",
        "userCreatedAt",
        "userId",
    ):
        assert field_name in operation.query
    assert "me {" not in operation.query


@pytest.mark.parametrize("invalid_value", ["true", 1, 0, [], {}, 1.5])
@pytest.mark.parametrize("field_name", ["hasAcceptedTerms", "isActivated", "isAvailableInCountry", "isAvailableOnSite"])
def test_feature_rejects_coerced_boolean_flags(field_name: str, invalid_value: object) -> None:
    """Reject malformed flags instead of interpreting truthy values as activation."""
    payload = {"isActivated": True, field_name: invalid_value}

    with pytest.raises(RequestException, match=f"Invalid Smart HVAC field '{field_name}'"):
        SmartHvac.from_dict(payload)


def test_feature_missing_fields_are_nullable() -> None:
    """Keep absent fields unknown rather than guessing the device is off."""
    feature = SmartHvac.from_dict({})

    assert feature is not None
    assert feature.isActivated is None
    assert feature.is_available_on_site is None
    assert feature.has_accepted_terms is None


@pytest.mark.parametrize("field_name", ["userCreatedAt", "userId"])
def test_feature_rejects_invalid_identity_fields(field_name: str) -> None:
    """Reject malformed metadata without disclosing values in exceptions."""
    with pytest.raises(RequestException, match=f"Invalid Smart HVAC field '{field_name}'"):
        SmartHvac.from_dict({field_name: 14})


def test_me_parser_also_validates_feature_flags() -> None:
    """Apply strict parsing to the combined Me response added by the earlier PR."""
    with pytest.raises(RequestException, match="Invalid Smart HVAC field 'isActivated'"):
        Me.from_dict({"data": {"me": {"id": "synthetic-user"}, "userSmartHvac": {"isActivated": "false"}}})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"data": {}},
        {"data": {"userSmartHvac": "unavailable"}},
        {"data": {"userSmartHvac": []}},
        {"errors": [{"message": "Graphql validation error"}]},
    ],
)
async def test_site_status_rejects_incomplete_or_malformed_responses(
    api: FrankEnergie,
    payload: dict[str, object],
) -> None:
    """Do not convert upstream response corruption into feature absence."""
    with (
        patch.object(api, "_query", new=AsyncMock(return_value=payload)),
        pytest.raises(RequestException),
    ):
        await api.smart_hvac_status("1234AB 10")


@pytest.mark.asyncio
async def test_site_status_null_then_recovers(api: FrankEnergie) -> None:
    """Unsupported accounts can return null, then report a valid state later."""
    responses = [{"data": {"userSmartHvac": None}}, _feature_response(activated=False, available_on_site=True)]
    with patch.object(api, "_query", new=AsyncMock(side_effect=responses)):
        assert await api.smart_hvac_status("1234AB 10") is None
        result = await api.smart_hvac_status("1234AB 10")
    assert result is not None
    assert result.isActivated is False
    assert result.is_available_on_site is True


@pytest.mark.asyncio
async def test_status_failure_then_recovers(api: FrankEnergie) -> None:
    """Request failures must not turn into cached empty status."""
    with patch.object(
        api,
        "_query",
        new=AsyncMock(side_effect=[RequestException("API unavailable"), _feature_response()]),
    ):
        with pytest.raises(RequestException, match="API unavailable"):
            await api.smart_hvac_status("1234AB 10")
        recovered = await api.smart_hvac_status("1234AB 10")
    assert recovered is not None
    assert recovered.isActivated is True


@pytest.mark.parametrize(
    "message",
    ["Graphql validation error", "request-error:request-not-supported-in-country", "opaque-private-upstream-error"],
)
def test_smart_hvac_graphql_failures_are_private(
    api: FrankEnergie,
    caplog: pytest.LogCaptureFixture,
    message: str,
) -> None:
    """Surface safe errors without logging nested personal identifiers."""
    fake_private_id = "synthetic-private-identifier"
    errors = {
        "errors": [
            {"message": message, "path": [fake_private_id], "extensions": {"reference": fake_private_id}},
        ]
    }

    with (
        caplog.at_level(logging.DEBUG),
        pytest.raises(RequestException) as error_info,
    ):
        api._handle_errors(errors, "UserSmartHvac")

    assert fake_private_id not in str(error_info.value)
    assert fake_private_id not in caplog.text


@pytest.mark.parametrize(
    "method_name,args",
    [
        ("smart_hvac_status", ("1234AB 10",)),
        ("smart_hvacs", ("1234AB 10",)),
        ("smart_hvac", ("synthetic-device",)),
        ("smart_hvac_summary", ("synthetic-device",)),
        ("smart_hvac_connect_requests", ()),
    ],
)
@pytest.mark.asyncio
async def test_smart_hvac_methods_require_authentication(method_name: str, args: tuple[object, ...]) -> None:
    """Require authentication uniformly across all Smart HVAC endpoints."""
    client = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await getattr(client, method_name)(*args)


@pytest.mark.parametrize(
    "method_name",
    ["smart_hvac_status", "smart_hvacs", "smart_hvac", "smart_hvac_summary"],
)
@pytest.mark.parametrize("identifier", [None, 12, "", " \t "])
@pytest.mark.asyncio
async def test_smart_hvac_identifiers_are_required(api: FrankEnergie, method_name: str, identifier: object) -> None:
    """Reject blank or non-string IDs before issuing requests."""
    with pytest.raises(ValueError, match="valid non-empty"):
        await getattr(api, method_name)(identifier)


@pytest.mark.asyncio
async def test_smart_hvac_methods_preserve_auth_errors(api: FrankEnergie) -> None:
    """Propagate typed reauthentication failures without hiding them as null."""
    with (
        patch.object(api, "_query", new=AsyncMock(side_effect=AuthRequiredException("Authentication required"))),
        pytest.raises(AuthRequiredException),
    ):
        await api.smart_hvac_status("1234AB 10")


@pytest.mark.asyncio
async def test_smart_hvac_inventory_and_single_device_are_distinct(api: FrankEnergie) -> None:
    """Parse observed device inventory fields without mixing them into user activation."""
    device = {
        "id": "synthetic-device",
        "brand": "NIBE",
        "connectionEAN": "synthetic-ean",
        "createdAt": "2025-10-28T17:42:07.149Z",
        "deletedAt": None,
        "deviceType": "heat_pump",
        "displayName": "Example HVAC",
        "needsReauthentication": False,
        "externalReference": "synthetic-external",
        "model": "Example",
        "provider": "NOX",
        "updatedAt": "2026-11-08T13:11:28.447Z",
    }
    with patch.object(
        api,
        "_query",
        new=AsyncMock(
            side_effect=[
                {"data": {"smartHvacs": [device]}},
                {"data": {"smartHvac": device}},
            ]
        ),
    ) as query_mock:
        devices = await api.smart_hvacs("1234AB 10")
        individual = await api.smart_hvac("synthetic-device")

    assert len(devices) == 1
    assert individual == devices[0]
    assert individual.id == "synthetic-device"
    assert individual.needs_reauthentication is False
    assert individual.created_at == datetime(2025, 10, 28, 17, 42, 7, 149000, tzinfo=UTC)
    assert individual.updated_at is not None and individual.updated_at.tzinfo is not None
    assert query_mock.call_args_list[0].args[0].variables == {"siteReference": "1234AB 10"}
    assert query_mock.call_args_list[1].args[0].variables == {"deviceId": "synthetic-device"}
    assert query_mock.call_args_list[0].args[0].operation_name == "SmartHvacs"
    assert query_mock.call_args_list[1].args[0].operation_name == "SmartHvac"


@pytest.mark.asyncio
async def test_inventory_allows_explicit_empty_list_but_not_null(api: FrankEnergie) -> None:
    """Distinguish an empty inventory from a missing or corrupt inventory."""
    with patch.object(api, "_query", new=AsyncMock(return_value={"data": {"smartHvacs": []}})):
        assert await api.smart_hvacs("1234AB 10") == []
    with (
        patch.object(api, "_query", new=AsyncMock(return_value={"data": {"smartHvacs": None}})),
        pytest.raises(RequestException, match="expected a list"),
    ):
        await api.smart_hvacs("1234AB 10")


@pytest.mark.asyncio
async def test_inventory_rejects_invalid_or_duplicate_devices(api: FrankEnergie) -> None:
    """Fail atomically rather than silently dropping malformed device records."""
    for inventory in ([{"id": "synthetic"}, {"id": "synthetic"}], [{"id": ""}], ["invalid-record"]):
        with (
            patch.object(api, "_query", new=AsyncMock(return_value={"data": {"smartHvacs": inventory}})),
            pytest.raises(RequestException),
        ):
            await api.smart_hvacs("1234AB 10")


@pytest.mark.asyncio
async def test_single_device_accepts_explicit_null(api: FrankEnergie) -> None:
    """Expose a null device without manufacturing a placeholder device."""
    with patch.object(api, "_query", new=AsyncMock(return_value={"data": {"smartHvac": None}})):
        assert await api.smart_hvac("synthetic-device") is None


@pytest.mark.asyncio
async def test_summary_preserves_raw_provider_status(api: FrankEnergie) -> None:
    """Keep raw ACTIVE statuses distinct from inferred heating or steering."""
    response = {
        "data": {
            "smartHvacSummary": {
                "firstSessionDate": "2025-12-22",
                "lastSessionDate": "2026-11-07",
                "operationalStatus": "ACTIVE",
                "operationalStatusTimestamp": "2026-11-08T13:34:18.082Z",
                "steeringStatus": "ACTIVE",
                "totalResult": 0,
            }
        }
    }
    with patch.object(api, "_query", new=AsyncMock(return_value=response)) as request:
        summary = await api.smart_hvac_summary("synthetic-device")
    assert summary is not None
    assert summary.first_session_date == date(2025, 12, 22)
    assert summary.last_session_date == date(2026, 11, 7)
    assert summary.operational_status == "ACTIVE"
    assert summary.steering_status == "ACTIVE"
    assert summary.operational_status_timestamp is not None
    assert summary.operational_status_timestamp.tzinfo == UTC
    assert summary.total_result == 0.0
    assert request.call_args.args[0].operation_name == "SmartHvacSummary"
    assert request.call_args.args[0].variables == {"deviceId": "synthetic-device"}


@pytest.mark.parametrize(
    "payload",
    [
        {"operationalStatusTimestamp": "2026-11-08T13:34:18"},
        {"operationalStatusTimestamp": "not-a-date"},
        {"firstSessionDate": "not-a-date"},
        {"totalResult": True},
        {"totalResult": float("inf")},
    ],
)
@pytest.mark.asyncio
async def test_summary_rejects_malformed_fields(api: FrankEnergie, payload: dict[str, object]) -> None:
    """Reject malformed timestamps and numeric result rather than inventing values."""
    with (
        patch.object(api, "_query", new=AsyncMock(return_value={"data": {"smartHvacSummary": payload}})),
        pytest.raises(RequestException),
    ):
        await api.smart_hvac_summary("synthetic-device")


@pytest.mark.asyncio
async def test_connect_requests_empty_and_typed(api: FrankEnergie) -> None:
    """Handle independently queried connect requests with opaque status strings."""
    with patch.object(
        api,
        "_query",
        new=AsyncMock(
            side_effect=[
                {"data": {"smartHvacConnectRequests": []}},
                {
                    "data": {
                        "smartHvacConnectRequests": [
                            {
                                "id": "synthetic-request",
                                "brand": "NIBE",
                                "error": None,
                                "status": "opaque-provider-status",
                            }
                        ]
                    }
                },
            ]
        ),
    ) as request:
        assert await api.smart_hvac_connect_requests() == []
        result = await api.smart_hvac_connect_requests()
    assert len(result) == 1
    assert result[0].id == "synthetic-request"
    assert result[0].status == "opaque-provider-status"
    assert request.call_args.args[0].operation_name == "SmartHvacGetConnectRequests"
    assert request.call_args.args[0].variables == {}


@pytest.mark.asyncio
async def test_connect_requests_reject_missing_or_invalid_list(api: FrankEnergie) -> None:
    """Do not confuse an invalid connect-request response with zero requests."""
    for payload in (
        {"data": {}},
        {"data": {"smartHvacConnectRequests": None}},
        {"data": {"smartHvacConnectRequests": [None]}},
    ):
        with (
            patch.object(api, "_query", new=AsyncMock(return_value=payload)),
            pytest.raises(RequestException),
        ):
            await api.smart_hvac_connect_requests()
