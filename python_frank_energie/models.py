# python_frank_energie/models.py

"""Data models enable parsing and processing of the Frank Energie API responses in a structured manner."""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone, tzinfo
from typing import Any, Set, Union

from pydantic import BaseModel

from .exceptions import RequestException

DEFAULT_ROUND = 6

_LOGGER: logging.Logger = logging.getLogger(__name__)

VERSION = "2025.5.23"
FETCH_TOMORROW_HOUR_UTC = 12

@dataclass
class Authentication:
    """Authentication data...
    """
    authToken: str
    refreshToken: str
    expires_at: datetime | None = None

    @staticmethod
    def from_dict(data: dict[str, str]) -> 'Authentication':
        ...
        # (unchanged)

    @staticmethod
    def _extract_payload(data: dict) -> dict | None:
        ...
    def old_authTokenValid(self, tz: timezone = timezone.utc) -> bool:
        ...
    def old_auth_token_valid(self, tz: tzinfo = timezone.utc) -> bool:
        ...
    @property
    def is_expired(self) -> bool:
        ...

@dataclass
class Invoice:
    ...
    @property
    def for_last_year(self) -> bool:
        ...
    @property
    def for_this_year(self) -> bool:
        ...
    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'Invoice' | None:
        ...

@dataclass
class Invoices:
    """Represents invoices including historical, current, and upcoming periods."""

    def __init__(
        self,
        allPeriodsInvoices: list[Invoice | None] = None,
        previousPeriodInvoice: Invoice | None = None,
        currentPeriodInvoice: Invoice | None = None,
        upcomingPeriodInvoice: Invoice | None = None,
        AllInvoicesDictForPreviousYear: dict | None = None,
        AllInvoicesDictForThisYear: dict | None = None,
        AllInvoicesDict: dict | None = None,
        TotalCostsPreviousYear: float = 0.0,
        TotalCostsThisYear: float = 0.0,
    ):
        # Ensure defaults are real collections if not provided

        if allPeriodsInvoices is None:
            allPeriodsInvoices = []
        if AllInvoicesDictForPreviousYear is None:
            AllInvoicesDictForPreviousYear = {}
        if AllInvoicesDictForThisYear is None:
            AllInvoicesDictForThisYear = {}
        if AllInvoicesDict is None:
            AllInvoicesDict = {}

        self.allPeriodsInvoices = allPeriodsInvoices
        self.previousPeriodInvoice = previousPeriodInvoice
        self.currentPeriodInvoice = currentPeriodInvoice
        self.upcomingPeriodInvoice = upcomingPeriodInvoice
        self.AllInvoicesDictForPreviousYear = AllInvoicesDictForPreviousYear
        self.AllInvoicesDictForThisYear = AllInvoicesDictForThisYear
        self.AllInvoicesDict = AllInvoicesDict
        self.TotalCostsPreviousYear = TotalCostsPreviousYear
        self.TotalCostsThisYear = TotalCostsThisYear

    def get_all_invoices_dict_for_previous_year(self) -> dict:
        ...
    def get_all_invoices_dict_for_this_year(self) -> dict:
        ...
    def get_all_invoices_dict_per_year(self) -> dict:
        ...
    def get_all_invoices_dict(self) -> dict:
        ...
    def get_invoices_for_year(self, year: int) -> list['Invoice']:
        ...
    def calculate_total_costs(self, year: int) -> float:
        ...
    def calculate_average_costs_per_month(self, year: int = None) -> float | None:
        ...
    def calculate_expected_costs_this_year(self) -> float | None:
        ...
    def get_unique_years(self) -> Set[int]:
        ...
    def calculate_average_costs_per_year(self) -> float | None:
        ...
    def calculate_average_costs_per_month_this_year(self) -> float | None:
        ...
    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'Invoices':
        ...

@dataclass
class UsageItem:
    ...

@dataclass
class EnergyCategory:
    ...

@dataclass
class PeriodUsageAndCosts:
    ...

@dataclass
class UserSites:
    ...

@dataclass
class Me:
    ...

def get_segments(data: dict[str, Any]) -> list[str | None]:
    ...

@dataclass
class Address:
    ...
    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Address":
        ...

class DeliverySite(BaseModel):
    ...
    @staticmethod
    def from_dict(payload: dict[str, str]) -> 'DeliverySite':
        ...

@dataclass
class Person:
    ...
@dataclass
class Contact:
    ...
@dataclass
class Email:
    ...
@dataclass
class Debtor:
    ...
@dataclass
class GridOperatorAddress:
    ...
@dataclass
class ExternalDetails:
    ...
@dataclass
class Connection:
    ...
@dataclass
class MeterReadingExportPeriod:
    ...
class UserDetails:
    ...
@dataclass
class Signup:
    ...
@dataclass
class UserSettings:
    ...
@dataclass
class activePaymentAuthorization:
    ...
@dataclass
class InviteLinkUser:
    ...
@dataclass
class Organization:
    ...
@dataclass
class PushNotificationPriceAlert:
    ...
@dataclass
class SmartCharging:
    ...
@dataclass
class SmartTrading:
    ...
@dataclass
class DeliverySiteFormat:
    ...
@dataclass
class DeliverySiteList:
    ...

class DailyConsumption:
    ...
class EnergyConsumption:
    ...

@dataclass
class User:
    ...
    @staticmethod
    def from_dict(data: dict[str, Any]) -> "User" | None:
        ...

@dataclass
class MonthInsights:
    ...
    @staticmethod
    def from_dict(data: dict[str, str]) -> Union['MonthInsights', None]:
        ...

@dataclass
class MonthSummary:
    ...
    @staticmethod
    def from_dict(data: dict[str, str]) -> 'MonthSummary' | None:
        ...
    @staticmethod
    def calculate_expected_costs_per_day(expected_costs: float, lastMeterReadingDate: datetime) -> float:
        ...
    @staticmethod
    def calculate_costs_per_day_till_now(costs_till_now: float, lastMeterReadingDate: datetime) -> float:
        ...
    @property
    def differenceUntilLastMeterReadingDate(self) -> float:
        ...
    @property
    def differenceUntilLastMeterReadingDateAvg(self) -> float:
        ...

@dataclass
class ChargeSettings:
    ...
@dataclass
class ChargeState:
    ...
@dataclass
class Intervention:
    ...
@dataclass
class EnodeCharger:
    ...
    @classmethod
    def from_dict(cls, data: dict) -> 'EnodeCharger':
        ...

@dataclass
class EnodeChargers:
    ...
    @classmethod
    def from_dict(cls, data: list[dict]) -> 'EnodeChargers':
        ...

@dataclass
class Price:
    date_from: datetime
    date_till: datetime
    price_data: list['Price']
    energy_type: str | None = None
    market_price: float = 0.0
    market_price_tax: float = 0.0
    sourcing_markup_price: float = 0.0
    energy_tax_price: float = 0.0
    # 'total', 'per_unit', 'unit', 'tax_rate', 'tax', 'start_time', 'timestamp' defined later by __init__

    def __post_init__(self):
        ...

    def __init__(self, data: dict, energy_type: str | None = None) -> None:
        ...
        self.market_price = data["marketPrice"]
        self.market_price_tax = data["marketPriceTax"]
        self.sourcing_markup_price = data["sourcingMarkupPrice"]
        self.energy_tax_price = data["energyTaxPrice"]
        self.market_price_including_tax = self.market_price + self.market_price_tax
        self.market_price_including_tax_and_markup = (
            self.market_price + self.market_price_tax + self.sourcing_markup_price
        )
        self.per_unit = data.get('perUnit')
        self.unit = data.get('unit')
        self.tax_rate = data.get('taxRate', 0.0)
        self.tax = data.get('tax', 0.0)
        # compute total on demand in property below

    def __str__(self) -> str:
        return "%s -> %s: %.4f %s" % (
            self.date_from.isoformat() if self.date_from else "N/A",
            self.date_till.isoformat() if self.date_till else "N/A",
            self.total,
            self.unit or ""
        )

    @property
    def ET(self, data) -> str:
        ...
    @property
    def for_now(self) -> bool:
        ...
    @property
    def for_future(self) -> bool:
        ...
    @property
    def for_today(self) -> bool:
        ...
    @property
    def for_tomorrow(self) -> bool:
        ...
    @property
    def for_upcoming(self) -> bool:
        ...
    @property
    def for_previous_hour(self) -> bool:
        ...
    @property
    def for_next_hour(self) -> bool:
        ...
    @property
    def total(self) -> float:
        if not hasattr(self, '_total'):
            self._total = (
                self.market_price
                + self.market_price_tax
                + self.sourcing_markup_price
                + self.energy_tax_price
            )
        return self._total

class PriceData:
    ...
    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'MarketPrices':
        _LOGGER.debug("Prices %s", data)

        errors = data.get("errors")
        if errors and errors[0]["message"].startswith("No marketprices found for segment"):
            return MarketPrices(PriceData(), PriceData())
        # raise RequestException(errors[0]["message"])

        payload = data.get("data")
        if payload is None:
            return None

        # (rest unchanged)

    @staticmethod
    def from_be_dict(cls, data: dict[str, Any]) -> 'MarketPrices':
        ...
        try:
            payload = data.get("data").get("marketPrices", {})
        except KeyError as err:
            raise ValueError("Invalid response format: %s" % err) from err

    @staticmethod
    def from_userprices_dict(data: dict[str, Any]) -> 'MarketPrices' | None:
        ...
        if errors := data.get("errors"):
            if errors[0]["message"].startswith("No marketprices found for segment"):
                return MarketPrices(PriceData(), PriceData())
            raise RequestException(errors[0]["message"])
        ...

@dataclass
class SmartBatteries:
    ...
    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'SmartBatteries':
        ...

@dataclass
class SmartBatterySettings:
    ...

@dataclass
class SmartBattery:
    ...

@dataclass
class SmartBatterySession:
    ...

@dataclass
class SmartBatterySessions:
    ...
    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'SmartBatterySessions':
        ...
        sb_data = data.get("smartBattery", {})
        if not sb_data:
            raise RequestException("Unexpected response")

        _LOGGER.debug("SmartBatteryDetails %s", sb_data)
        ...
        try:
            created_at = datetime.fromisoformat(created_at_str).astimezone(timezone.utc) if created_at_str else None
        except Exception:
            _LOGGER.warning("Invalid or missing 'createdAt' in smart battery data: %s", created_at_str)
            created_at = None

        try:
            updated_at = datetime.fromisoformat(updated_at_str).astimezone(timezone.utc) if updated_at_str else None
        except Exception:
            _LOGGER.warning("Invalid or missing 'updatedAt' in smart battery data: %s", updated_at_str)
            updated_at = None

        summary_data = data.get("smartBatterySummary", {})
        # The next line was redundant and has been removed:
        # last_update = datetime.fromisoformat(summary_data["lastMeterReadingDate"].replace("Z", "+00:00"))

        smart_battery_summary = SmartBatterySummary.from_dict(summary_data)
        ...

# (rest of file unchanged)