"""Typed, privacy-safe parsing of weighted average price results."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

from .exceptions import RequestException


def _require_object(value: object, field_name: str) -> Mapping[str, object]:
    """Require a JSON object without including its possibly private contents in errors."""
    if not isinstance(value, Mapping):
        raise RequestException(f"Expected an object for '{field_name}' in WeightedAveragePrices response.")
    return value


def _require_string(data: Mapping[str, object], field_name: str, context: str) -> str:
    """Read a required nonempty string without altering the provider's value."""
    value = data.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise RequestException(f"Missing or invalid '{field_name}' in {context}.")
    return value


def _nullable_price(data: Mapping[str, object], field_name: str, context: str) -> float | None:
    """Return a finite GraphQL numeric price or an explicitly returned null."""
    if field_name not in data:
        raise RequestException(f"Missing '{field_name}' in {context}.")
    value = data[field_name]
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RequestException(f"Invalid numeric '{field_name}' in {context}.")
    price = float(value)
    if not math.isfinite(price):
        raise RequestException(f"Non-finite '{field_name}' in {context}.")
    return price


def _nullable_unit(data: Mapping[str, object], context: str) -> str | None:
    """Keep an explicitly null unit distinct from a missing unit."""
    if "perUnit" not in data:
        raise RequestException(f"Missing 'perUnit' in {context}.")
    unit = data["perUnit"]
    if unit is not None and (not isinstance(unit, str) or not unit.strip()):
        raise RequestException(f"Invalid 'perUnit' in {context}.")
    return unit


@dataclass(slots=True)
class WeightedAveragePriceItem:
    """Represent a provider-reported weighted price for one subperiod."""

    _id: str
    date: str
    from_time: str
    till_time: str
    average_market_price: float | None
    average_market_price_plus: float | None
    per_unit: str | None

    @classmethod
    def from_dict(cls, value: object) -> WeightedAveragePriceItem:
        """Parse one weighted price item while preserving provider timestamps."""
        data = _require_object(value, "items[]")
        context = "WeightedAveragePrices.items[]"
        return cls(
            _id=_require_string(data, "_id", context),
            date=_require_string(data, "date", context),
            from_time=_require_string(data, "from", context),
            till_time=_require_string(data, "till", context),
            average_market_price=_nullable_price(data, "averageMarketPrice", context),
            average_market_price_plus=_nullable_price(data, "averageMarketPricePlus", context),
            per_unit=_nullable_unit(data, context),
        )


@dataclass(slots=True)
class WeightedAveragePriceCategory:
    """Represent weighted prices and individual entries for one energy category."""

    average_market_price: float | None
    average_market_price_plus: float | None
    per_unit: str | None
    items: list[WeightedAveragePriceItem]

    @classmethod
    def from_dict(cls, value: object, category_name: str) -> WeightedAveragePriceCategory:
        """Parse the category and reject an absent or invalid item collection."""
        data = _require_object(value, category_name)
        context = f"WeightedAveragePrices.{category_name}"
        entries = data.get("items")
        if not isinstance(entries, list):
            raise RequestException(f"Missing or invalid 'items' in {context}.")
        return cls(
            average_market_price=_nullable_price(data, "averageMarketPrice", context),
            average_market_price_plus=_nullable_price(data, "averageMarketPricePlus", context),
            per_unit=_nullable_unit(data, context),
            items=[WeightedAveragePriceItem.from_dict(item) for item in entries],
        )


@dataclass(slots=True)
class WeightedAveragePrices:
    """Contain provider weighted prices for gas, electricity, and feed-in."""

    _id: str
    gas: WeightedAveragePriceCategory | None
    electricity: WeightedAveragePriceCategory | None
    feed_in: WeightedAveragePriceCategory | None

    @classmethod
    def from_dict(cls, response: object) -> WeightedAveragePrices:
        """Parse a complete successful GraphQL response without inventing missing data."""
        payload = _require_object(response, "response")
        if "errors" in payload and payload["errors"] != []:
            raise RequestException("WeightedAveragePrices GraphQL response contains errors.")
        data = _require_object(payload.get("data"), "data")
        period = _require_object(data.get("weightedAveragePrices"), "weightedAveragePrices")

        def category(name: str) -> WeightedAveragePriceCategory | None:
            """Distinguish an explicitly null category from a missing one."""
            if name not in period:
                raise RequestException(f"Missing '{name}' in WeightedAveragePrices response.")
            value = period[name]
            return None if value is None else WeightedAveragePriceCategory.from_dict(value, name)

        return cls(
            _id=_require_string(period, "_id", "WeightedAveragePrices"),
            gas=category("gas"),
            electricity=category("electricity"),
            feed_in=category("feedIn"),
        )
