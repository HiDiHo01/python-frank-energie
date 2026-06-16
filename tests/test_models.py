"""Tests for Frank Energie Models."""

import json

import pytest
from freezegun import freeze_time
from syrupy.assertion import SnapshotAssertion

from python_frank_energie.exceptions import AuthException, RequestException
from python_frank_energie.models import (
    Authentication,
    Connection,
    Invoices,
    MarketPrices,
    Me,
    MonthSummary,
    User,
)

from . import load_fixtures

#
# Tests for Authentication Model.
#


def test_authentication_with_expected_parameters():
    """Test Authentication.from_dict with expected parameters."""
    auth = Authentication.from_dict(json.loads(load_fixtures("authentication.json")))
    assert auth
    assert auth.authToken == "hello"
    assert auth.refreshToken == "world"


def test_authentication_with_missing_parameters():
    """Test Authentication.from_dict with missing parameters."""
    with pytest.raises(AuthException) as excinfo:
        Authentication.from_dict({})

    assert "Unexpected response" in str(excinfo.value)


def test_authentication_with_unexpected_response():
    """Test Authentication.from_dict with unexpected response."""
    with pytest.raises(AuthException):
        Authentication.from_dict({"data": {"login": None}})


def test_authentication_error_message():
    """Test Authentication.from_dict with error message."""
    with pytest.raises(AuthException) as excinfo:
        Authentication.from_dict({"errors": [{"message": "help me"}]})

    assert "help me" in str(excinfo.value)


#
# Tests for Me Model.
#


def test_me_with_expected_parameters(snapshot: SnapshotAssertion):
    """Test Me.from_dict with expected parameters."""
    me = Me.from_dict(json.loads(load_fixtures("me.json")))
    assert me
    assert me == snapshot


def test_me_with_missing_parameters():
    """Test Me.from_dict with missing parameters."""
    with pytest.raises(RequestException) as excinfo:
        Me.from_dict({})

    assert "Unexpected response" in str(excinfo.value)


def test_me_with_unexpected_response():
    """Test Me.from_dict with unexpected response."""
    with pytest.raises(RequestException):
        Me.from_dict({"data": {"me": None}})


def test_me_error_message():
    """Test Me.from_dict with error message."""
    with pytest.raises(RequestException) as excinfo:
        Me.from_dict({"errors": [{"message": "help me"}]})

    assert "help me" in str(excinfo.value)


#
# Tests for User Model.
#


def test_user_with_expected_parameters():
    """Test User.from_dict parses connections as Connection objects."""
    user = User.from_dict(json.loads(load_fixtures("me.json")))
    assert user
    assert len(user.connections) > 0
    assert all(isinstance(conn, Connection) for conn in user.connections)
    
    # Attribute access
    conn = user.connections[0]
    assert conn.connectionId == "d1v9jvd1jnj0-vd1j09jb-1vd-vfwdon"
    
    # Dict-like access (for backwards compatibility with HA custom component)
    assert conn["connectionId"] == "d1v9jvd1jnj0-vd1j09jb-1vd-vfwdon"
    assert conn.get("connectionId") == "d1v9jvd1jnj0-vd1j09jb-1vd-vfwdon"
    assert conn.get("estimatedFeedIn") == 0
    assert conn.get("nonExistentKey", "default") == "default"
    
    ext = conn.get("externalDetails")
    assert ext is not None
    assert ext.get("gridOperator") == "Stedin"
    
    addr = ext.get("address")
    assert addr is not None
    assert addr.get("city") == "AMSTERDAM"


#
# Tests for MonthSummary Model.
#


def test_month_summary_with_expected_parameters(snapshot: SnapshotAssertion):
    """Test MonthSummary.from_dict with expected parameters."""
    month_summary = MonthSummary.from_dict(json.loads(load_fixtures("month_summary.json")))
    assert month_summary
    assert month_summary == snapshot


def test_month_summary_with_missing_parameters():
    """Empty payload (no summary yet) should resolve to ``None`` rather than raise.

    Frank Energie does not publish the previous month's invoice for the first
    few days of a new billing month; the coordinator must tolerate that gap.
    """
    assert MonthSummary.from_dict({}) is None


def test_month_summary_with_none_payload():
    """``data.monthSummary: null`` is a normal transient state -> ``None``."""
    assert MonthSummary.from_dict({"data": {"monthSummary": None}}) is None


def test_month_summary_with_empty_payload():
    """``data.monthSummary: {}`` is a normal transient state -> ``None``."""
    assert MonthSummary.from_dict({"data": {"monthSummary": {}}}) is None


def test_month_summary_with_all_null_fields():
    """All summary fields null -> ``None`` (defense-in-depth)."""
    payload = {
        "data": {
            "monthSummary": {
                "expectedCosts": None,
                "lastMeterReadingDate": None,
                "actualCostsUntilLastMeterReadingDate": None,
            }
        }
    }
    assert MonthSummary.from_dict(payload) is None


def test_month_summary_error_message():
    """Test MonthSummary.from_dict with error message."""
    with pytest.raises(RequestException) as excinfo:
        MonthSummary.from_dict({"errors": [{"message": "help me"}]})

    assert "help me" in str(excinfo.value)


def test_month_summary_malformed_populated_payload_still_raises():
    """A populated-but-malformed summary must still raise (schema-drift signal)."""
    payload = {
        "data": {
            "monthSummary": {
                "expectedCosts": "not-a-number",
                "lastMeterReadingDate": "2026-05-31",
                "actualCostsUntilLastMeterReadingDate": 12.34,
            }
        }
    }
    with pytest.raises(RequestException) as excinfo:
        MonthSummary.from_dict(payload)
    assert "Invalid expectedCosts" in str(excinfo.value)


@pytest.mark.parametrize(
    "bad_payload",
    ["not-a-dict", ["list", "instead"], 42],
    ids=["string", "list", "int"],
)
def test_month_summary_non_dict_payload_raises(bad_payload):
    """A truthy non-dict monthSummary value is schema drift -> raise."""
    with pytest.raises(RequestException) as excinfo:
        MonthSummary.from_dict({"data": {"monthSummary": bad_payload}})
    assert "Unexpected monthSummary payload type" in str(excinfo.value)


#
# Tests for MarketPrices Model.
#


def test_market_prices_with_expected_parameters():
    """Test MarketPrices.from_dict with expected parameters."""
    market_prices = MarketPrices.from_dict(json.loads(load_fixtures("market_prices.json")))

    assert market_prices
    assert len(market_prices.electricity.price_data) == 24
    assert len(market_prices.gas.price_data) == 24


def test_market_prices_with_missing_parameters():
    """Test MarketPrices.from_dict with missing parameters."""
    with pytest.raises(RequestException) as excinfo:
        MarketPrices.from_dict({})

    assert "Unexpected response" in str(excinfo.value)


def test_market_prices_error_message():
    """Test MarketPrices.from_dict with error message."""
    with pytest.raises(RequestException) as excinfo:
        MarketPrices.from_dict({"errors": [{"message": "help me"}]})

    assert "help me" in str(excinfo.value)


@freeze_time("2022-11-21 14:15:00")
def test_market_prices_pricedata_current_hour():
    """Test functionality of MarketPrices.price_data."""
    market_prices = MarketPrices.from_dict(json.loads(load_fixtures("market_prices.json")))

    assert market_prices.electricity.current_hour.market_price == 1.14
    assert market_prices.electricity.current_hour.market_price_tax == 2.14
    assert market_prices.electricity.current_hour.sourcing_markup_price == 3.14
    assert market_prices.electricity.current_hour.energy_tax_price == 4.14
    assert market_prices.electricity.current_hour.market_price_with_tax == 3.28
    assert market_prices.electricity.current_hour.total == 10.56
    assert market_prices.electricity.current_hour.for_now is True
    assert market_prices.electricity.current_hour.for_future is False
    assert market_prices.electricity.current_hour.for_today is True

    assert market_prices.electricity.today_min.total == 10.0
    assert market_prices.electricity.today_max.total == 13.996
    assert market_prices.electricity.today_avg == 11.2175


@freeze_time("2022-11-21 14:15:00")
def test_market_prices_pricedata_next_hour():
    """Test functionality of MarketPrices.price_data."""
    market_prices = MarketPrices.from_dict(json.loads(load_fixtures("market_prices.json")))

    future_prices = market_prices.electricity.get_future_prices()
    assert len(future_prices) == 9
    assert future_prices[0].market_price == 1.15
    assert future_prices[1].market_price == 1.16


#
# Tests for Invoices Model.
#


def test_invoices_with_expected_parameters(snapshot: SnapshotAssertion):
    """Test Invoices.from_dict with expected parameters."""
    invoices = Invoices.from_dict(json.loads(load_fixtures("invoices.json")))

    assert invoices
    assert invoices == snapshot


def test_invoices_with_missing_parameters():
    """Test Invoices.from_dict with missing parameters."""
    with pytest.raises(RequestException) as excinfo:
        Invoices.from_dict({})

    assert "Unexpected response" in str(excinfo.value)


def test_invoices_error_message():
    """Test Invoices.from_dict with error message."""
    with pytest.raises(RequestException) as excinfo:
        Invoices.from_dict({"errors": [{"message": "help me"}]})

    assert "help me" in str(excinfo.value)


def test_invoices_none_data():
    """Test Invoices.from_dict with None data."""
    invoices = Invoices.from_dict(
        {
            "data": {
                "invoices": {
                    "previousPeriodInvoice": None,
                    "currentPeriodInvoice": None,
                    "upcomingPeriodInvoice": None,
                }
            }
        }
    )

    assert invoices.previousPeriodInvoice is None
    assert invoices.currentPeriodInvoice is None
    assert invoices.upcomingPeriodInvoice is None
