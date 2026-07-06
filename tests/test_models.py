"""Tests for Frank Energie Models."""

import json

import pytest
from freezegun import freeze_time
from syrupy.assertion import SnapshotAssertion

from python_frank_energie.domain import SmartBatteryImbalanceStrategy, SmartBatteryMode
from python_frank_energie.exceptions import AuthException, NoMarketPricesAvailableException, RequestException
from python_frank_energie.models import (
    Authentication,
    ChargeState,
    Connection,
    EnergyCategory,
    EnodeCharger,
    EnodeChargers,
    Invoices,
    MarketPrices,
    Me,
    MonthSummary,
    SmartBatterySettings,
    SmartHvac,
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

    assert "Missing 'data' in authentication response" in str(excinfo.value)


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

    assert "Missing 'data' in response" in str(excinfo.value)


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


def test_user_connections_missing():
    """User.from_dict with no 'connections' key returns an empty list."""
    minimal_payload = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
            }
        }
    }
    user = User.from_dict(minimal_payload)
    assert user.connections == []


def test_user_connections_empty_list():
    """User.from_dict with an empty connections array returns an empty list."""
    payload = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
                "connections": [],
            }
        }
    }
    user = User.from_dict(payload)
    assert user.connections == []


def test_user_connections_non_dict_items_skipped():
    """Non-dict entries in connections are silently skipped, no exception raised."""
    payload = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
                "connections": [
                    None,
                    "not-a-dict",
                    42,
                    {"id": "conn-1", "segment": "ELECTRICITY"},  # only this should survive
                ],
            }
        }
    }
    user = User.from_dict(payload)
    assert len(user.connections) == 1
    assert isinstance(user.connections[0], Connection)
    assert user.connections[0].segment == "ELECTRICITY"


def test_user_datetime_z_suffix_parses():
    """createdAt/updatedAt/lastLogin with trailing Z parse to datetime, not None."""
    payload = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
                "lastLogin": "2024-05-01T12:00:00Z",
                "createdAt": "2023-01-15T08:30:00Z",
                "updatedAt": "2024-06-01T00:00:00Z",
            }
        }
    }
    user = User.from_dict(payload)
    assert user.lastLogin is not None, "lastLogin should parse with Z suffix"
    assert user.createdAt is not None, "createdAt should parse with Z suffix"
    assert user.updatedAt is not None, "updatedAt should parse with Z suffix"
    assert user.lastLogin.tzinfo is not None, "lastLogin should be timezone-aware"


def test_user_smart_hvac_parses():
    """smartHvac field is parsed correctly from user payload."""
    payload = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
                "smartHvac": {
                    "isActivated": True,
                    "isAvailableInCountry": True,
                    "userCreatedAt": "2026-06-20T17:00:00Z",
                    "userId": "test-user-id",
                },
            }
        }
    }
    user = User.from_dict(payload)
    assert user.smartHvac == SmartHvac(
        isActivated=True,
        isAvailableInCountry=True,
        userCreatedAt="2026-06-20T17:00:00Z",
        userId="test-user-id",
    )


def test_user_smart_hvac_parses_missing_and_null():
    """smartHvac parses correctly when missing, null, or partially populated."""
    # 1. Missing smartHvac
    payload_missing = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
            }
        }
    }
    user_missing = User.from_dict(payload_missing)
    assert user_missing.smartHvac is None

    # 2. Null smartHvac
    payload_null = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
                "smartHvac": None,
            }
        }
    }
    user_null = User.from_dict(payload_null)
    assert user_null.smartHvac is None

    # 3. Partially populated smartHvac
    payload_partial = {
        "data": {
            "me": {
                "id": "test-id",
                "email": "test@example.com",
                "smartHvac": {
                    "isActivated": False,
                },
            }
        }
    }
    user_partial = User.from_dict(payload_partial)
    assert user_partial.smartHvac == SmartHvac(
        isActivated=False,
        isAvailableInCountry=None,
        userCreatedAt=None,
        userId=None,
    )


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
    assert MonthSummary.from_dict({"data": {}}) is None


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
                "_id": "summary_123",
                "actualCostsUntilLastMeterReadingDate": 12.34,
                "expectedCostsUntilLastMeterReadingDate": 20.0,
                "expectedCosts": "not-a-number",
                "lastMeterReadingDate": "2026-05-31",
                "meterReadingDayCompleteness": 1,
                "gasExcluded": False,
                "__typename": "MonthSummary",
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

    assert "Missing 'data' in NL response" in str(excinfo.value)


def test_market_prices_error_message():
    """Test MarketPrices.from_dict with error message."""
    with pytest.raises(RequestException) as excinfo:
        MarketPrices.from_dict({"errors": [{"message": "help me"}]})

    assert "help me" in str(excinfo.value)


def test_market_prices_no_market_prices_available_nl():
    """Test MarketPrices.from_dict raises NoMarketPricesAvailableException for NL 'No marketprices found' errors."""
    with pytest.raises(NoMarketPricesAvailableException) as excinfo:
        MarketPrices.from_dict(
            {"errors": [{"message": "No marketprices found for segment ELECTRICITY for 2026-07-02"}]}
        )

    assert "No marketprices found" in str(excinfo.value)


def test_market_prices_no_market_prices_available_be():
    """Test MarketPrices.from_be_dict raises NoMarketPricesAvailableException for BE 'No marketprices found' errors."""
    with pytest.raises(NoMarketPricesAvailableException) as excinfo:
        MarketPrices.from_be_dict(
            {"errors": [{"message": "No marketprices found for segment ELECTRICITY for 2026-07-02"}]}
        )

    assert "No marketprices found" in str(excinfo.value)


@freeze_time("2022-11-21 14:15:00")
def test_market_prices_pricedata_current_hour():
    """Test functionality of MarketPrices.price_data."""
    market_prices = MarketPrices.from_dict(json.loads(load_fixtures("market_prices.json")))

    assert market_prices.electricity.current_hour.market_price == 1.14
    assert market_prices.electricity.current_hour.market_price_tax == 2.14
    assert market_prices.electricity.current_hour.sourcing_markup_price == 3.14
    assert market_prices.electricity.current_hour.energy_tax_price == 4.14
    assert market_prices.electricity.current_hour.market_price_with_tax == pytest.approx(3.28)
    assert market_prices.electricity.current_hour.total == pytest.approx(10.56)
    assert market_prices.electricity.current_hour.for_now is True
    assert market_prices.electricity.current_hour.for_future is False
    assert market_prices.electricity.current_hour.for_today is True

    assert market_prices.electricity.today_min.total == pytest.approx(10.0)
    assert market_prices.electricity.today_max.total == pytest.approx(13.996)
    assert market_prices.electricity.today_avg == pytest.approx(11.230434782608695)


@freeze_time("2022-11-21 14:15:00")
def test_market_prices_pricedata_next_hour():
    """Test functionality of MarketPrices.price_data."""
    market_prices = MarketPrices.from_dict(json.loads(load_fixtures("market_prices.json")))

    future_prices = market_prices.electricity.upcoming
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

    assert "Invalid invoices payload" in str(excinfo.value)


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

    assert invoices.previous_period_invoice is None
    assert invoices.current_period_invoice is None
    assert invoices.upcoming_period_invoice is None


def test_price_and_pricedata_per_unit():
    """Test that per_unit property is parsed and exposed correctly on Price and PriceData models."""
    from python_frank_energie.models import Price, PriceData, PriceDataAvg

    price_dict = {
        "from": "2026-06-16T20:00:00.000Z",
        "till": "2026-06-16T21:00:00.000Z",
        "marketPrice": 0.052,
        "marketPriceTax": 0.01,
        "sourcingMarkupPrice": 0.005,
        "energyTaxPrice": 0.02,
        "perUnit": "KWH",
    }

    price = Price(price_dict, energy_type="gas")
    assert price.per_unit == "KWH"

    price_data = PriceData(prices=[price_dict], energy_type="gas")
    assert price_data.per_unit == "KWH"

    avg_price_data = PriceDataAvg(
        values=[price],
        total=0.087,
        market_price_with_tax_and_markup=0.067,
        market_markup_price=0.005,
        market_price_with_tax=0.062,
        market_price_tax=0.01,
        market_price=0.052,
    )
    assert avg_price_data.per_unit == "KWH"


#
# Tests for EnodeCharger / ChargeState Models (regression: no-car scenario).
#
# When a charger has no vehicle attached, the Frank Energie API returns None
# for battery_capacity, battery_level, charge_limit, range, and is_fully_charged.
# Previously these crashed with TypeError (float(None)), causing the entire
# charger list to be silently swallowed by the exception handler in frank_energie.py.
#


_CHARGER_NO_CAR = {
    "canSmartCharge": True,
    "chargeSettings": {
        "calculatedDeadline": "2025-03-24T06:00:00.000Z",
        "capacity": 22,
        "deadline": None,
        "hourFriday": 420,
        "hourMonday": 420,
        "hourSaturday": 420,
        "hourSunday": 420,
        "hourThursday": 420,
        "hourTuesday": 420,
        "hourWednesday": 420,
        "id": "test-charger-id-001",
        "initialCharge": 0,
        "initialChargeTimestamp": "2024-11-21T19:00:15.396Z",
        "isSmartChargingEnabled": True,
        "isSolarChargingEnabled": False,
        "maxChargeLimit": 80,
        "minChargeLimit": 20,
    },
    "chargeState": {
        # All nullable fields are None — the API state when no car is attached.
        "batteryCapacity": None,
        "batteryLevel": None,
        "chargeLimit": None,
        "chargeRate": None,
        "chargeTimeRemaining": None,
        "isCharging": False,
        "isFullyCharged": None,
        "isPluggedIn": False,
        "lastUpdated": "2025-03-23T16:06:57.000Z",
        "powerDeliveryState": "UNPLUGGED",
        "range": None,
    },
    "id": "test-charger-id-001",
    "information": {"brand": "Wallbox", "model": "Pulsar Plus", "year": None},
    "interventions": [],
    "isReachable": True,
    "lastSeen": "2025-03-23T16:24:51.913Z",
}


class TestChargeStateNoCarScenario:
    """Regression tests for EV charger with no car attached (nullable fields)."""

    def test_charge_state_from_dict_all_nullable_none(self):
        """ChargeState.from_dict must not crash when vehicle-specific fields are None."""
        state = ChargeState.from_dict(_CHARGER_NO_CAR["chargeState"])

        assert state.battery_capacity is None
        assert state.battery_level is None
        assert state.charge_limit is None
        assert state.charge_rate is None
        assert state.is_fully_charged is None
        assert state.range is None
        # Non-nullable fields should still be parsed correctly.
        assert state.is_charging is False
        assert state.is_plugged_in is False
        assert state.power_delivery_state == "UNPLUGGED"

    def test_enode_charger_from_dict_no_car(self):
        """EnodeCharger.from_dict must succeed when chargeState has all-None nullable fields."""
        charger = EnodeCharger.from_dict(_CHARGER_NO_CAR)

        assert charger.id == "test-charger-id-001"
        assert charger.can_smart_charge is True
        assert charger.is_reachable is True
        assert charger.charge_state.battery_capacity is None
        assert charger.charge_state.battery_level is None
        assert charger.charge_state.charge_limit is None
        assert charger.charge_state.range is None
        assert charger.charge_state.is_fully_charged is None
        assert charger.charge_state.power_delivery_state == "UNPLUGGED"

    def test_enode_chargers_from_dict_no_car(self):
        """EnodeChargers.from_dict must return a valid object for a no-car charger list."""
        chargers_obj = EnodeChargers.from_dict([_CHARGER_NO_CAR])

        assert len(chargers_obj.chargers) == 1
        charger = chargers_obj.chargers[0]
        assert charger.id == "test-charger-id-001"
        assert charger.charge_state.battery_level is None

    def test_enode_chargers_from_dict_empty_list(self):
        """EnodeChargers.from_dict with an empty list returns zero chargers."""
        chargers_obj = EnodeChargers.from_dict([])
        assert chargers_obj.chargers == []

    def test_charge_state_from_dict_with_car_attached(self):
        """ChargeState.from_dict must parse non-None values correctly when a car is attached."""
        data = {
            "batteryCapacity": 75.0,
            "batteryLevel": 60,
            "chargeLimit": 80,
            "chargeRate": 10.71,
            "chargeTimeRemaining": None,
            "isCharging": True,
            "isFullyCharged": False,
            "isPluggedIn": True,
            "lastUpdated": "2025-03-23T16:23:53.000Z",
            "powerDeliveryState": "PLUGGED_IN:CHARGING",
            "range": 250,
        }
        state = ChargeState.from_dict(data)

        assert state.battery_capacity == pytest.approx(75.0)
        assert state.battery_level == 60
        assert state.charge_limit == 80
        assert state.charge_rate == pytest.approx(10.71)
        assert state.is_fully_charged is False
        assert state.range == 250
        assert state.is_charging is True


class TestEnergyCategory:
    """Tests for the EnergyCategory model, specifically around null-handling for Issue #79."""

    def test_energy_category_with_valid_usage_and_costs(self):
        """Test parsing when usageTotal and costsTotal are populated floats."""
        data = {
            "usageTotal": 12.34,
            "costsTotal": 5.67,
            "unit": "KWH",
            "items": [],
        }
        category = EnergyCategory.from_dict(data)
        assert category.usage_total == pytest.approx(12.34)
        assert category.costs_total == pytest.approx(5.67)
        assert category.unit == "KWH"

    def test_energy_category_with_none_values(self):
        """Test parsing when usageTotal and costsTotal are None (Issue #79)."""
        data = {
            "usageTotal": None,
            "costsTotal": None,
            "unit": "KWH",
            "items": [],
        }
        category = EnergyCategory.from_dict(data)
        assert category.usage_total is None
        assert category.costs_total is None
        assert category.unit == "KWH"

    def test_energy_category_with_missing_keys(self):
        """Test parsing when usageTotal and costsTotal are missing (Issue #79)."""
        data = {
            "unit": "KWH",
            "items": [],
        }
        category = EnergyCategory.from_dict(data)
        assert category.usage_total is None
        assert category.costs_total is None
        assert category.unit == "KWH"


def test_smart_battery_settings_from_dict_defensive_parsing_unknown_enum_values() -> None:
    """SmartBatterySettings.from_dict should defensively map unexpected upstream enum values to UNKNOWN."""
    raw = {
        "batteryMode": "WRONG_MODE",
        "imbalanceTradingStrategy": "WRONG_STRATEGY",
        "selfConsumptionTradingThresholdPrice": 0.25,
    }

    settings = SmartBatterySettings.from_dict(raw)

    assert settings.battery_mode is SmartBatteryMode.UNKNOWN
    assert settings.imbalance_trading_strategy is SmartBatteryImbalanceStrategy.UNKNOWN
    assert settings.self_consumption_trading_threshold_price == 0.25
