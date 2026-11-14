"""Regression coverage for the provider-backed nullable MonthInsights contract."""

import asyncio
import json
import logging
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import (
    AuthException,
    FrankEnergieException,
    NetworkError,
    RateLimitException,
    RequestException,
)
from python_frank_energie.models import Difference, MonthInsights

_GRAPHQL_HOST = "frank-graphql-prod.graphcdn.app"
_SECRET = "synthetic-private-connection-id"
_DIFFERENCE = {
    "actualUsage": 133.261,
    "actualAverageUnitPrice": 0.3247,
    "actualCosts": 43.27,
    "expectedUsage": 145.6,
    "expectedAverageUnitPrice": 0.2415,
    "expectedCosts": 35.16,
    "unit": "KWH",
}


def _month_payload(**changes: object) -> dict[str, object]:
    """Build a synthetic example of the observed November 2026 provider response."""
    return {
        "_id": "synthetic-site|2026-11",
        "expectedCosts": 108.51,
        "expectedCostsGas": 0,
        "expectedCostsFixed": 27.37,
        "expectedCostsElectricity": 81.14,
        "expectedCostsFeedIn": 0,
        "expectedCostsUntilLastMeterReading": 47.02,
        "actualCostsUntilLastMeterReading": 55.13,
        "lastMeterReadingDate": "2026-11-13",
        "invoiceId": "synthetic-invoice",
        "gasDifference": None,
        "electricityDifference": _DIFFERENCE.copy(),
        "feedInDifference": None,
        "meterReadingDayCompleteness": 1,
        "gasExcluded": False,
        **changes,
    }


def _parse_month(**changes: object) -> MonthInsights:
    """Parse a complete response and require a populated MonthInsights model."""
    parsed = MonthInsights.from_dict({"data": {"monthInsights": _month_payload(**changes)}})
    assert parsed is not None
    return parsed


def test_observed_null_blocks_and_genuine_zeros() -> None:
    """Never fabricate gas or feed-in differences from provider nulls."""
    insights = _parse_month()
    assert insights.expectedCostsGas == 0.0
    assert insights.expectedCostsFeedIn == 0.0
    assert insights.gasExcluded is False
    assert insights.gasDifference is None
    assert insights.feedInDifference is None
    assert insights.electricityDifference is not None
    assert insights.electricityDifference.unit == "KWH"
    assert insights.electricityDifference.actualUsage == pytest.approx(133.261)
    assert insights.meterReadingDayCompleteness == 1.0
    assert insights.lastMeterReadingDate == datetime(2026, 11, 13, tzinfo=UTC)


def test_observed_negative_feed_in_remains_numeric() -> None:
    """Preserve negative feed-in readings independently of gas exclusion."""
    feed_in_difference = {
        **_DIFFERENCE,
        "actualUsage": -78.429,
        "actualCosts": -26.17,
        "expectedUsage": -30.3333,
        "expectedCosts": -7.95,
    }
    insights = _parse_month(expectedCostsFeedIn=-18.34, feedInDifference=feed_in_difference)
    assert insights.feedInDifference is not None
    assert insights.feedInDifference.actualUsage == pytest.approx(-78.429)
    assert insights.feedInDifference.actualCosts == pytest.approx(-26.17)
    assert insights.feedInDifference.expectedCosts == pytest.approx(-7.95)
    assert insights.expectedCostsFeedIn == pytest.approx(-18.34)
    assert insights.gasDifference is None


@pytest.mark.parametrize("block_name", ("gasDifference", "electricityDifference", "feedInDifference"))
@pytest.mark.parametrize("block_value", (None, "not-an-object", [], 42))
def test_nullable_and_invalid_difference_blocks(block_name: str, block_value: object) -> None:
    """Nullable blocks stay absent; malformed non-null blocks are rejected."""
    if block_value is None:
        insights = _parse_month(**{block_name: None})
        assert getattr(insights, block_name) is None
    else:
        with pytest.raises(RequestException, match="difference block"):
            _parse_month(**{block_name: block_value})


def test_missing_difference_block_does_not_become_zeros() -> None:
    """A completely omitted comparison remains None."""
    payload = _month_payload()
    del payload["electricityDifference"]
    parsed = MonthInsights.from_dict({"data": {"monthInsights": payload}})
    assert parsed is not None
    assert parsed.electricityDifference is None


def test_genuine_all_zero_difference_is_preserved() -> None:
    """An actual provider-shaped all-zero object is not mistaken for null."""
    zero_block = {key: 0 for key in _DIFFERENCE if key != "unit"}
    zero_block["unit"] = ""
    insights = _parse_month(gasDifference=zero_block)
    assert insights.gasDifference is not None
    assert insights.gasDifference.actualCosts == 0.0
    assert insights.gasDifference.expectedUsage == 0.0
    assert insights.gasDifference.unit == ""


@pytest.mark.parametrize("field_name", ("expectedCosts", "expectedCostsGas", "expectedCostsFixed",
                                        "expectedCostsElectricity", "expectedCostsFeedIn",
                                        "expectedCostsUntilLastMeterReading", "actualCostsUntilLastMeterReading",
                                        "meterReadingDayCompleteness"))
def test_null_and_omitted_month_numbers_are_unavailable(field_name: str) -> None:
    """Both explicit null and absent number fields map to None, not zero."""
    assert getattr(_parse_month(**{field_name: None}), field_name) is None
    payload = _month_payload()
    del payload[field_name]
    parsed = MonthInsights.from_dict({"data": {"monthInsights": payload}})
    assert parsed is not None
    assert getattr(parsed, field_name) is None


@pytest.mark.parametrize("invalid", (True, "NaN", "Infinity", "-Infinity", "", "not-a-number", [], {}))
def test_invalid_month_numbers_are_rejected(invalid: object) -> None:
    """Reject malformed non-null cost values rather than manufacturing zero."""
    with pytest.raises(RequestException, match="expectedCostsGas"):
        _parse_month(expectedCostsGas=invalid)


def test_partial_difference_keeps_nullable_numbers_and_unit() -> None:
    """Partial comparison fields and absent units remain genuinely unavailable."""
    insights = _parse_month(electricityDifference={"actualCosts": 0, "unit": None})
    assert insights.electricityDifference is not None
    assert insights.electricityDifference.actualCosts == 0.0
    assert insights.electricityDifference.actualUsage is None
    assert insights.electricityDifference.unit is None


@pytest.mark.parametrize("invalid", (True, "NaN", "Infinity", [], {}, "nonnumeric"))
def test_malformed_difference_numbers_are_rejected(invalid: object) -> None:
    """Reject malformed comparison metrics without exposing their raw values."""
    with pytest.raises(RequestException, match="actualCosts"):
        Difference.from_dict({"actualCosts": invalid})


@pytest.mark.parametrize("unit", (None, "", "KWH", "M3"))
def test_difference_unit_is_preserved(unit: str | None) -> None:
    """Preserve provider units and distinguish blank from missing."""
    assert Difference.from_dict({"unit": unit}).unit == unit


@pytest.mark.parametrize("unit", (0, True, [], {}))
def test_invalid_unit_is_rejected(unit: object) -> None:
    """Do not stringify malformed units."""
    with pytest.raises(RequestException, match="unit"):
        Difference.from_dict({"unit": unit})


@pytest.mark.parametrize("value", (True, False, None))
def test_gas_excluded_preserves_tristate(value: bool | None) -> None:
    """Keep gasExcluded independent of gasDifference availability."""
    assert _parse_month(gasExcluded=value).gasExcluded is value


def test_missing_gas_excluded_is_unknown() -> None:
    """Do not infer false from an absent gas exclusion flag."""
    payload = _month_payload()
    del payload["gasExcluded"]
    parsed = MonthInsights.from_dict({"data": {"monthInsights": payload}})
    assert parsed is not None
    assert parsed.gasExcluded is None


@pytest.mark.parametrize("invalid", ("false", 0, 1, [], {}))
def test_invalid_gas_excluded_is_rejected(invalid: object) -> None:
    """Non-boolean flags may not silently become true or false."""
    with pytest.raises(RequestException, match="gasExcluded"):
        _parse_month(gasExcluded=invalid)


@pytest.mark.parametrize(
    ("source_date", "expected_date"),
    (
        ("2026-11-13", datetime(2026, 11, 13, tzinfo=UTC)),
        ("2026-11-13T01:00:00+01:00", datetime(2026, 11, 13, tzinfo=UTC)),
        ("2026-11-13T00:00:00Z", datetime(2026, 11, 13, tzinfo=UTC)),
        (None, None),
    ),
)
def test_meter_date_is_optional_and_utc(source_date: str | None, expected_date: datetime | None) -> None:
    """Normalize present dates, preserving null readings as unavailable."""
    assert _parse_month(lastMeterReadingDate=source_date).lastMeterReadingDate == expected_date


def test_missing_date_remains_unavailable() -> None:
    """Do not discard an otherwise valid forecast without a meter date."""
    payload = _month_payload()
    del payload["lastMeterReadingDate"]
    parsed = MonthInsights.from_dict({"data": {"monthInsights": payload}})
    assert parsed is not None
    assert parsed.lastMeterReadingDate is None


@pytest.mark.parametrize("invalid", ("", "2026-13-45", 42, True, {}, []))
def test_invalid_date_is_sanitized(invalid: object) -> None:
    """Reject invalid timestamps without embedding user-provided values."""
    with pytest.raises(RequestException, match="Invalid MonthInsights lastMeterReadingDate") as error:
        _parse_month(lastMeterReadingDate=invalid)
    assert str(error.value) == "Invalid MonthInsights lastMeterReadingDate"


def test_constructor_retains_field_order_and_nullable_date() -> None:
    """Keep positional model construction while permitting optional reading dates."""
    insights = _parse_month()
    insights.lastMeterReadingDate = None
    insights.__post_init__()
    assert insights.lastMeterReadingDate is None


@pytest.mark.parametrize(
    "response",
    (
        {},
        {"data": None},
        {"data": {}},
        {"data": {"other": None}},
        {"data": {"monthInsights": []}},
        {"errors": {"message": "sensitive"}, "data": {"monthInsights": None}},
        {"data": {"monthInsights": None}, "errors": [{"message": "private-data"}]},
    ),
)
def test_malformed_envelopes_are_rejected_without_raw_errors(response: dict[str, object]) -> None:
    """Missing or malformed GraphQL structure is not a successful no-data result."""
    with pytest.raises(RequestException) as error:
        MonthInsights.from_dict(response)
    assert "private-data" not in str(error.value)
    assert "sensitive" not in str(error.value)


def test_explicit_null_without_errors_returns_none() -> None:
    """An explicitly null successful MonthInsights field has its own result state."""
    assert MonthInsights.from_dict({"data": {"monthInsights": None}}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("period", ("2026", "2026-00", "2026-13", "2026-1", "2026-011",
                                    "0000-01", "2026-01 ", " 2026-01", "2026-０１",
                                    "2026-٠١", "", "junk", "2026-12\n"))
async def test_period_validation_does_not_call_api(period: str) -> None:
    """Reject non-YYYY-MM periods before any GraphQL call."""
    api = FrankEnergie(auth_token="synthetic-token")
    with patch.object(api, "_query", new_callable=AsyncMock) as query_mock:
        with pytest.raises(FrankEnergieException, match="YYYY-MM"):
            await api.month_insights("site", period)
        query_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_valid_period_is_forwarded_unchanged() -> None:
    """Send exactly one valid period without changing the public method signature."""
    api = FrankEnergie(auth_token="synthetic-token")
    with patch.object(api, "_query", new_callable=AsyncMock, return_value={"data": {"monthInsights": None}}) as mock:
        assert await api.month_insights("site", "2026-12") is None
        query = mock.await_args.args[0]
        assert query.operation_name == "MonthInsights"
        assert query.variables == {"siteReference": "site", "date": "2026-12"}


@pytest.mark.asyncio
@pytest.mark.parametrize("site_reference", ("", "  ", None, 123))
async def test_invalid_site_is_rejected_without_request(site_reference: object) -> None:
    """Prevent missing or malformed site references from reaching the provider."""
    api = FrankEnergie(auth_token="synthetic-token")
    with patch.object(api, "_query", new_callable=AsyncMock) as mock:
        with pytest.raises(FrankEnergieException, match="site_reference"):
            await api.month_insights(site_reference, "2026-11")
        mock.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    (
        RateLimitException("MonthInsights", retry_after=20),
        AuthException("Authentication required"),
        NetworkError("Network failure"),
        RequestException("Invalid request"),
        asyncio.CancelledError(),
    ),
)
async def test_typed_errors_and_cancellation_are_not_wrapped(failure: BaseException) -> None:
    """Preserve exception type, rate-limit delay and cancellation."""
    api = FrankEnergie(auth_token="synthetic-token")
    with (
        patch.object(api, "_query", new_callable=AsyncMock, side_effect=failure),
        pytest.raises(type(failure)) as exc_info,
    ):
        await api.month_insights("site", "2026-11")
    assert exc_info.value is failure
    if isinstance(failure, RateLimitException):
        assert failure.retry_after == 20


def _add_response(aresponses: object, data: dict[str, object]) -> None:
    """Register one synthetic HTTP GraphQL response."""
    aresponses.add(
        _GRAPHQL_HOST,
        "/",
        "POST",
        aresponses.Response(
            text=json.dumps(data),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )


@pytest.mark.asyncio
async def test_observed_missing_readings_returns_none_without_identifier(aresponses: object, caplog: object) -> None:
    """The single verified missing-readings error is a safe unavailable result."""
    payload = {
        "data": {"monthInsights": None},
        "errors": [
            {
                "message": f"Could not find a first or last meter reading for {_SECRET} on 2026-12",
                "path": ["monthInsights"],
                "locations": [{"line": 2, "column": 3}],
            }
        ],
    }
    _add_response(aresponses, payload)
    caplog.set_level(logging.DEBUG)
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="synthetic-token")
        assert await api.month_insights("synthetic-site", "2026-12") is None
    assert _SECRET not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("wrong-path", "multiple-errors", "non-null-payload"))
async def test_unrecognized_reading_errors_fail_closed_without_logging_ids(
    aresponses: object, caplog: object, mode: str
) -> None:
    """Do not swallow errors with mismatched paths, multiple errors or usable payloads."""
    error = {
        "message": f"Could not find a first or last meter reading for {_SECRET} on 2026-12",
        "path": ["monthInsights"],
    }
    response = {"data": {"monthInsights": None}, "errors": [error]}
    if mode == "wrong-path":
        error["path"] = ["monthSummary"]
    elif mode == "multiple-errors":
        response["errors"].append({"message": "another-private-secret", "path": ["monthInsights"]})
    else:
        response["data"]["monthInsights"] = _month_payload()
    _add_response(aresponses, response)
    caplog.set_level(logging.DEBUG)
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="synthetic-token")
        with pytest.raises(RequestException) as exc_info:
            await api.month_insights("synthetic-site", "2026-12")
    assert _SECRET not in caplog.text
    assert "another-private-secret" not in caplog.text
    assert _SECRET not in str(exc_info.value)


@pytest.mark.asyncio
async def test_real_transport_keeps_nullable_payload_values(aresponses: object) -> None:
    """Verify the HTTP-to-model path does not replace null differences with zeros."""
    _add_response(aresponses, {"data": {"monthInsights": _month_payload()}})
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="synthetic-token")
        insights = await api.month_insights("synthetic-site", "2026-11")
    assert insights is not None
    assert insights.expectedCostsGas == 0.0
    assert insights.gasDifference is None
    assert insights.feedInDifference is None
