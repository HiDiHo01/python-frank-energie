"""Tests for the WeightedAveragePrices GraphQL operation and typed models."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from unittest.mock import AsyncMock, patch

import pytest

from python_frank_energie import FrankEnergie, WeightedAveragePrices
from python_frank_energie.exceptions import AuthRequiredException, NetworkError, RequestException
from python_frank_energie.weighted_average_prices import WeightedAveragePriceCategory, WeightedAveragePriceItem

# Schema-shaped fixtures are synthetic. No live WeightedAveragePrices response was provided.
_ITEM = {
    "_id": "synthetic-price-item",
    "date": "2025-03-01",
    "from": "2025-03-01T00:00:00.000Z",
    "till": "2025-03-01T00:15:00.000Z",
    "averageMarketPrice": -0.05,
    "averageMarketPricePlus": -0.03,
    "perUnit": "KWH",
}
_ELECTRICITY = {
    "averageMarketPrice": -0.02,
    "averageMarketPricePlus": 0.01,
    "perUnit": "KWH",
    "items": [_ITEM],
}
_RESULT = {
    "_id": "synthetic-month",
    "gas": None,
    "electricity": _ELECTRICITY,
    "feedIn": {"averageMarketPrice": None, "averageMarketPricePlus": None, "perUnit": None, "items": []},
}
_RESPONSE = {"data": {"weightedAveragePrices": _RESULT}}


@pytest.mark.asyncio
async def test_weighted_average_prices_builds_exact_named_query() -> None:
    """Pass the observed YYYY-MM month and site reference to the expected query."""
    client = FrankEnergie(auth_token="synthetic-token")
    with patch.object(client, "_query", new_callable=AsyncMock, return_value=_RESPONSE) as request:
        result = await client.weighted_average_prices(site_reference="synthetic-site", month="2025-03")

    request.assert_awaited_once()
    sent_query = request.await_args.args[0]
    assert sent_query.operation_name == "WeightedAveragePrices"
    assert sent_query.variables == {"date": "2025-03", "siteReference": "synthetic-site"}
    assert "query WeightedAveragePrices($date: String!, $siteReference: String!)" in sent_query.query
    assert "weightedAveragePrices(date: $date, siteReference: $siteReference)" in sent_query.query
    for selection in ("gas {", "electricity {", "feedIn {", "averageMarketPrice", "averageMarketPricePlus"):
        assert selection in sent_query.query
    assert sent_query.query.count("items {") == 3
    assert sent_query.query.count("perUnit") == 6

    assert isinstance(result, WeightedAveragePrices)
    assert result._id == "synthetic-month"
    assert result.gas is None
    assert isinstance(result.electricity, WeightedAveragePriceCategory)
    assert result.electricity.average_market_price == -0.02
    assert result.electricity.average_market_price_plus == 0.01
    assert result.electricity.per_unit == "KWH"
    assert len(result.electricity.items) == 1
    item = result.electricity.items[0]
    assert isinstance(item, WeightedAveragePriceItem)
    assert item._id == "synthetic-price-item"
    assert item.from_time == "2025-03-01T00:00:00.000Z"
    assert item.till_time == "2025-03-01T00:15:00.000Z"
    assert item.average_market_price == -0.05
    assert item.average_market_price_plus == -0.03
    assert result.feed_in is not None
    assert result.feed_in.items == []
    assert result.feed_in.average_market_price is None


@pytest.mark.asyncio
async def test_weighted_average_prices_requires_authentication() -> None:
    """Do not send a request for an unauthenticated client."""
    client = FrankEnergie()
    with (
        patch.object(client, "_query", new_callable=AsyncMock) as request,
        pytest.raises(AuthRequiredException, match="Authentication is required"),
    ):
        await client.weighted_average_prices("synthetic-site", "2025-03")
    request.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("site_reference", ("", "  ", None, 42))
async def test_weighted_average_prices_rejects_invalid_site_reference(site_reference: object) -> None:
    """Reject missing or malformed site references before sending API requests."""
    client = FrankEnergie(auth_token="synthetic-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock) as request,
        pytest.raises(ValueError, match="site_reference"),
    ):
        await client.weighted_average_prices(site_reference, "2025-03")
    request.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("month", ("", "2025", "2025-00", "2025-13", "2025-03-01", "2025-3", "0000-01", None, 202503))
async def test_weighted_average_prices_rejects_invalid_month(month: object) -> None:
    """Require the observed YYYY-MM date shape with a real calendar month."""
    client = FrankEnergie(auth_token="synthetic-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock) as request,
        pytest.raises(ValueError, match="month"),
    ):
        await client.weighted_average_prices("synthetic-site", month)
    request.assert_not_awaited()


@pytest.mark.parametrize(
    "response",
    (
        None,
        {},
        {"data": None},
        {"data": []},
        {"data": {}},
        {"data": {"weightedAveragePrices": None}},
        {"data": {"weightedAveragePrices": []}},
        {"data": {"weightedAveragePrices": {"_id": "only-id"}}},
        {"data": {"weightedAveragePrices": _RESULT}, "errors": None},
        {"data": {"weightedAveragePrices": _RESULT}, "errors": [{"message": "private-provider-data"}]},
    ),
)
def test_weighted_average_prices_rejects_invalid_top_level(response: object) -> None:
    """Never transform a missing or failed response into an empty inventory."""
    with pytest.raises(RequestException) as raised:
        WeightedAveragePrices.from_dict(response)
    assert "private-provider-data" not in str(raised.value)


@pytest.mark.parametrize("category", ("gas", "electricity", "feedIn"))
def test_weighted_average_prices_requires_category_keys(category: str) -> None:
    """Do not treat a missing category field as an explicit GraphQL null."""
    response = deepcopy(_RESPONSE)
    del response["data"]["weightedAveragePrices"][category]
    with pytest.raises(RequestException, match=category):
        WeightedAveragePrices.from_dict(response)


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("averageMarketPrice", True),
        ("averageMarketPrice", "0.25"),
        ("averageMarketPrice", float("nan")),
        ("averageMarketPricePlus", float("inf")),
        ("averageMarketPricePlus", []),
        ("perUnit", []),
        ("items", None),
        ("items", [None]),
        ("items", [_ITEM, "invalid"]),
    ),
)
def test_weighted_average_prices_rejects_malformed_category(field_name: str, invalid_value: object) -> None:
    """Validate a category without leaking any other values in exception text."""
    response = deepcopy(_RESPONSE)
    response["data"]["weightedAveragePrices"]["electricity"][field_name] = invalid_value
    with pytest.raises(RequestException) as raised:
        WeightedAveragePrices.from_dict(response)
    assert "synthetic-price-item" not in str(raised.value)


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("_id", None),
        ("date", 2),
        ("from", ""),
        ("till", None),
        ("averageMarketPrice", "0.23"),
        ("averageMarketPricePlus", float("-inf")),
        ("perUnit", True),
    ),
)
def test_weighted_average_prices_rejects_malformed_items(field_name: str, invalid_value: object) -> None:
    """Reject malformed item fields, including invalid numbers and dates."""
    response = deepcopy(_RESPONSE)
    response["data"]["weightedAveragePrices"]["electricity"]["items"][0][field_name] = invalid_value
    with pytest.raises(RequestException):
        WeightedAveragePrices.from_dict(response)


@pytest.mark.parametrize(
    "field_name", ("_id", "date", "from", "till", "averageMarketPrice", "averageMarketPricePlus", "perUnit")
)
def test_weighted_average_prices_rejects_missing_item_field(field_name: str) -> None:
    """Keep missing selected item fields distinct from explicit null fields."""
    response = deepcopy(_RESPONSE)
    del response["data"]["weightedAveragePrices"]["electricity"]["items"][0][field_name]
    with pytest.raises(RequestException):
        WeightedAveragePrices.from_dict(response)


def test_weighted_average_prices_preserves_zero_and_null_prices() -> None:
    """Allow a numeric zero and nullable price without replacing either value."""
    response = deepcopy(_RESPONSE)
    response["data"]["weightedAveragePrices"]["electricity"]["averageMarketPrice"] = 0
    response["data"]["weightedAveragePrices"]["electricity"]["items"][0]["averageMarketPricePlus"] = None
    result = WeightedAveragePrices.from_dict(response)
    assert result.electricity is not None
    assert result.electricity.average_market_price == 0.0
    assert result.electricity.items[0].average_market_price_plus is None


@pytest.mark.asyncio
@pytest.mark.parametrize("error", (NetworkError("synthetic-network-failure"), asyncio.CancelledError()))
async def test_weighted_average_prices_preserves_transport_errors(error: BaseException) -> None:
    """Allow network errors and task cancellation to propagate unmodified."""
    client = FrankEnergie(auth_token="synthetic-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, side_effect=error),
        pytest.raises(type(error)) as raised,
    ):
        await client.weighted_average_prices("synthetic-site", "2025-03")
    assert raised.value is error
