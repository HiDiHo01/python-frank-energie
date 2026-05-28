"""Tests for Frank Energie Models."""

import json

import pytest
from freezegun import freeze_time
from syrupy.assertion import SnapshotAssertion

from python_frank_energie.exceptions import AuthException, RequestException
from python_frank_energie.models import (
    Authentication,
    Invoices,
    MarketPrices,
    Me,
    MonthSummary,
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
# Tests for MonthSummary Model.
#


def test_month_summary_with_expected_parameters(snapshot: SnapshotAssertion):
    """Test MonthSummary.from_dict with expected parameters."""
    month_summary = MonthSummary.from_dict(json.loads(load_fixtures("month_summary.json")))
    assert month_summary
    assert month_summary == snapshot


def test_month_summary_with_missing_parameters():
    """Test MonthSummary.from_dict with missing parameters."""
    with pytest.raises(RequestException) as excinfo:
        MonthSummary.from_dict({})

    assert "Unexpected response" in str(excinfo.value)


def test_month_summary_with_unexpected_response():
    """Test MonthSummary.from_dict with unexpected response."""
    with pytest.raises(RequestException):
        MonthSummary.from_dict({"data": {"monthSummary": None}})


def test_month_summary_error_message():
    """Test MonthSummary.from_dict with error message."""
    with pytest.raises(RequestException) as excinfo:
        MonthSummary.from_dict({"errors": [{"message": "help me"}]})

    assert "help me" in str(excinfo.value)


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
