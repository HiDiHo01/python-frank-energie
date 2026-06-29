"""Data models enable parsing and processing of the Frank Energie API responses in a structured manner."""

# python_frank_energie/models.py
# version 2026.06.16
from __future__ import annotations

import calendar
import logging
import math
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from statistics import mean
from typing import Any, TypeVar
from zoneinfo import ZoneInfo

import jwt
from dateutil.parser import parse
from jwt.exceptions import InvalidTokenError
from pydantic import BaseModel, EmailStr

from .exceptions import AuthException, RequestException

try:
    from .time_periods import TimePeriod
except ImportError:
    # Fallback to absolute import if relative import fails
    from python_frank_energie.time_periods import TimePeriod

_LOGGER: logging.Logger = logging.getLogger(__name__)

DEFAULT_ROUND = 6
FETCH_TOMORROW_HOUR_UTC = 11
LOCAL_TZ = ZoneInfo("Europe/Amsterdam")
_UTC_SUFFIX = "+00:00"  # Replaces trailing 'Z' in ISO-8601 UTC timestamps from the API


def _safe_float(val: Any) -> float | None:
    """Safely convert a value to float, handling NaNs, Infs and rounding."""
    if val is None or val == "":
        return None
    try:
        f_val = float(val)
        if math.isnan(f_val) or math.isinf(f_val):
            return None
        return round(f_val, 5)
    except (TypeError, ValueError):
        return None


def _parse_iso_datetime(value: str | datetime | None, field_name: str = "datetime") -> datetime | None:
    """Parse an ISO-8601 datetime string (or passthrough an existing datetime) to a UTC-aware datetime.

    Python's ``datetime.fromisoformat`` accepts ``+00:00`` but rejects the
    trailing ``Z`` that the Frank Energie API commonly returns (e.g.
    ``2024-01-01T12:00:00Z``).  This helper normalises that suffix before
    parsing so valid timestamps are never silently dropped.

    Date-only strings (e.g. ``"2026-06-01"``) produce naive datetimes;
    these are pinned to UTC via ``replace(tzinfo=UTC)`` so that downstream
    comparisons against timezone-aware ``Price.date_from`` values do not raise
    ``TypeError``.

    Args:
        value: A raw ISO-8601 string, an existing ``datetime`` object, or None.
        field_name: Name used in warning messages to identify the field.

    Returns:
        A UTC-aware ``datetime`` object, or ``None`` when the input is empty or
        cannot be parsed.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", _UTC_SUFFIX))
        except ValueError:
            _LOGGER.warning("Invalid %s format: %s", field_name, value)
            return None
    # Ensure the result is always timezone-aware (UTC)
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_date(value: Any) -> date | None:
    """Parse a date from various formats.

    Handles:
    - None input
    - date object input
    - Valid ISO date string
    - ISO datetime string (with T)
    - Invalid input (returns None)
    """
    if isinstance(value, date):
        if isinstance(value, datetime):
            return value.date()
        return value
    if isinstance(value, str):
        try:
            # Extract only the YYYY-MM-DD part if a full ISO datetime is provided
            date_str = value.split("T")[0].split(" ")[0]
            return date.fromisoformat(date_str)
        except (ValueError, TypeError, IndexError):
            return None
    return None


class DictLikeMixin:
    """Mixin to allow dataclasses to be accessed like dictionaries for backwards compatibility."""

    def _normalize_key(self, key: str) -> str:
        """Normalize incoming keys to the attribute naming convention (snake_case)."""
        return "".join(["_" + c.lower() if c.isupper() else c for c in key]).lstrip("_")

    def __getitem__(self, key: str) -> Any:
        snake_key = self._normalize_key(key)
        if hasattr(self, snake_key):
            return getattr(self, snake_key)
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        snake_key = self._normalize_key(key)
        return hasattr(self, snake_key) or hasattr(self, key)


T = TypeVar("T")


def _require(data: dict[str, object], key: str) -> T:
    """Require a key to exist in a dict and not be None."""
    value = data.get(key)

    if value is None:
        raise KeyError(f"Missing required field: {key}")

    return value  # type: ignore[return-value]


def _as_dict(value: object, field_name: str) -> dict[str, object]:
    """Ensure value is a dict with string keys."""
    if not isinstance(value, dict):
        raise TypeError(f"Invalid type for {field_name}, expected dict")

    if not all(isinstance(k, str) for k in value):
        raise TypeError(f"Invalid keys in {field_name}, expected str keys")

    return value  # type: ignore[return-value]


class Resolution(StrEnum):
    PT15M = "PT15M"
    PT60M = "PT60M"


@dataclass(slots=True)
class ContractPriceResolutionChangeResultData:
    """Contract price resolution change result."""

    effective_date: date | None = None

    @classmethod
    def from_dict(
        cls,
        data: dict[str, object],
    ) -> ContractPriceResolutionChangeResultData:
        """Create an instance from an API response."""
        value = data.get("effectiveDate")

        if isinstance(value, str):
            try:
                value = date.fromisoformat(value)
            except ValueError:
                value = None
        elif not isinstance(value, date) and value is not None:
            value = None

        return cls(
            effective_date=value,
        )

    @property
    def effectiveDate(self) -> date | None:
        """Backward compatibility alias."""
        return self.effective_date


@dataclass
class ContractPriceResolutionChangeResult:
    """Result of a contract price resolution change request."""

    success: bool = False
    reason: str | None = None
    data: ContractPriceResolutionChangeResultData | None = None

    @classmethod
    def from_dict(
        cls,
        data: dict[str, object],
    ) -> ContractPriceResolutionChangeResult:
        """Create an instance from API response data."""

        result_data = data.get("data")

        parsed_data = (
            ContractPriceResolutionChangeResultData.from_dict(result_data) if isinstance(result_data, dict) else None
        )

        success_val = data.get("success", False)
        success = success_val.lower() in ("true", "1") if isinstance(success_val, str) else bool(success_val)

        reason_val = data.get("reason")
        reason = reason_val if isinstance(reason_val, str) else None

        return cls(
            success=success,
            reason=reason,
            data=parsed_data,
        )

    @property
    def effectiveDate(self) -> date | None:
        """Backward compatibility alias."""
        return self.data.effective_date if self.data is not None else None

    @property
    def effective_date(self) -> date | None:
        """Return the effective date of the resolution change, if available."""
        return self.data.effective_date if self.data is not None else None


@dataclass
class Authentication:
    """Authentication data.

    Generated by the login or renewToken mutation.

    authToken: The token to use for authenticated requests.
    refreshToken: The token to use to renew the authToken.
    """

    authToken: str
    refreshToken: str
    version: str | None
    token_expires_at: datetime | None = None
    refresh_token_expires_at: datetime | None = None
    TOKEN_RENEWAL_MARGIN = timedelta(minutes=5)

    @staticmethod
    def from_dict(data: dict[str, object]) -> Authentication:
        """Parse the response from the login or renewToken mutation."""
        _LOGGER.debug("Authentication response keys: %s", list(data.keys()))

        if (errors := data.get("errors")) and isinstance(errors, list) and errors:
            message = errors[0].get("message") if isinstance(errors[0], dict) else None
            raise AuthException(message or "Unknown authentication error")

        # --- Validate root data ---
        root = data.get("data")
        if not isinstance(root, dict):
            raise AuthException("Missing 'data' in authentication response")

        version = root.get("version")
        if version is not None and not isinstance(version, str):
            raise AuthException("Invalid version field")

        _LOGGER.debug("API version: %s", version)

        payload = Authentication._extract_payload(root)
        if not isinstance(payload, dict):
            raise AuthException("Missing login/renewToken payload")

        _LOGGER.debug("Authentication payload keys: %s", list(payload.keys()))

        auth_token = payload.get("authToken")
        if not isinstance(auth_token, str):
            raise AuthException("Invalid authToken")

        refresh_token = payload.get("refreshToken")
        if not isinstance(refresh_token, str):
            raise AuthException("Invalid refreshToken")

        # --- Expiry extraction ---
        token_expires_at: datetime | None = None
        try:
            decoded: dict[str, object] = jwt.decode(
                auth_token,
                options={"verify_signature": False},
                algorithms=["HS256"],
            )

            _LOGGER.debug("authToken decoded claims keys: %s", list(decoded.keys()))

            exp = decoded.get("exp")
            if not isinstance(exp, (int, float)):
                _LOGGER.warning("authToken missing 'exp' claim; treating as expired")
                raise AuthException("Missing or invalid 'exp' in JWT")

            token_expires_at = datetime.fromtimestamp(exp, tz=UTC)
            _LOGGER.debug("authToken expires at: %s", token_expires_at)

        except InvalidTokenError as err:
            _LOGGER.warning("Unable to decode authToken to extract expiration: %s", err)

        # --- Expiry extraction ---
        refresh_token_expires_at: datetime | None = None
        try:
            decoded: dict[str, object] = jwt.decode(
                refresh_token,
                options={"verify_signature": False},
                algorithms=["HS256"],
            )

            _LOGGER.debug("refreshToken decoded claims keys: %s", list(decoded.keys()))

            exp = decoded.get("exp")
            if not isinstance(exp, (int, float)):
                _LOGGER.warning("refreshToken missing 'exp' claim; treating as expired")
                raise AuthException("Missing or invalid 'exp' in JWT")

            refresh_token_expires_at = datetime.fromtimestamp(exp, tz=UTC)
            _LOGGER.debug("authToken expires at: %s", refresh_token_expires_at)

        except InvalidTokenError as err:
            _LOGGER.warning("Unable to decode refreshToken to extract expiration: %s", err)

        return Authentication(
            authToken=auth_token,
            refreshToken=refresh_token,
            token_expires_at=token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at,
            version=version,
        )

    @staticmethod
    def _extract_payload(data: dict[str, object]) -> dict[str, object] | None:
        """Extract the login or renewToken payload from the data dictionary."""
        login = data.get("login")
        if isinstance(login, dict):
            return login

        renew = data.get("renewToken")
        if isinstance(renew, dict):
            return renew

        return None

    @property
    def is_expired(self) -> bool:
        """Return True when the token is expired or about to expire based on the expires_at field."""
        if self.token_expires_at is None:
            # If the token is a dummy mock token (does not have JWT structure), do not treat it as expired.
            # This prevents unwanted renewToken calls in tests.
            return bool(self.authToken and len(self.authToken.split(".")) >= 3)

        # gives a 5-minute refresh window and avoids edge cases where a request starts just before expiration
        return datetime.now(UTC) >= (self.token_expires_at - self.TOKEN_RENEWAL_MARGIN)


@dataclass
class Invoice:
    """Represents invoice information, including the start date, period
    description, and total amount."""

    id: str
    StartDate: datetime
    PeriodDescription: str
    TotalAmount: float

    @property
    def for_last_year(self) -> bool:
        """Whether this invoice is for the previous calendar year."""

        now_utc = datetime.now(UTC)
        now_local = now_utc.astimezone(LOCAL_TZ)
        last_year = now_local.year - 1

        start_date = self.StartDate

        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=UTC)

        invoice_start_year = start_date.astimezone(LOCAL_TZ).year

        return invoice_start_year == last_year

    @property
    def for_this_year(self) -> bool:
        """Whether this invoice is for the current calendar year."""

        now_utc = datetime.now(UTC)
        now_local = now_utc.astimezone(LOCAL_TZ)
        current_year = now_local.year

        start_date = self.StartDate

        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=UTC)

        invoice_start_year = start_date.astimezone(LOCAL_TZ).year

        return invoice_start_year == current_year

    @staticmethod
    def from_dict(data: dict[str, object]) -> Invoice | None:
        """Parse the invoice from the API invoice query response."""
        if not data:
            return None

        data = _as_dict(data, "invoice")
        total_amount_raw = data.get("totalAmount")
        if total_amount_raw is None:
            raise RequestException("Missing totalAmount")
        start_date = parse(str(data.get("startDate")))

        # Interpreteer factuurdatums als lokale kalenderdatums
        start_date = Invoice._ensure_local_month_start(start_date)

        return Invoice(
            id=str(data.get("id")),
            StartDate=start_date,
            PeriodDescription=str(data.get("periodDescription")),
            TotalAmount=float(total_amount_raw),
        )

    @classmethod
    def from_list(cls, data_list: list[dict[str, object]]) -> list[Invoice]:
        """Parse a list of invoice dictionaries into Invoice objects."""
        invoices: list[Invoice] = []

        for data in data_list:
            invoice = cls.from_dict(data)

            if invoice is not None:
                invoices.append(invoice)

        return invoices

    @staticmethod
    def _ensure_local_month_start(date_time: datetime) -> datetime:
        """Ensure invoice start dates are localized to Europe/Amsterdam."""
        if date_time.tzinfo is None:
            return date_time.replace(tzinfo=LOCAL_TZ)

        return date_time.astimezone(LOCAL_TZ)

    @staticmethod
    def _ensure_utc(date_time: datetime) -> datetime:
        """Ensure a datetime is timezone-aware and normalized to UTC."""
        if date_time.tzinfo is None:
            return date_time.replace(tzinfo=UTC)

        return date_time.astimezone(UTC)


@dataclass
class Invoices:
    """Represents invoices including historical, current, and upcoming periods."""

    all_periods_invoices: list[Invoice] = field(default_factory=list)
    previous_period_invoice: Invoice | None = None
    current_period_invoice: Invoice | None = None
    upcoming_period_invoice: Invoice | None = None

    all_invoices_dict_previous_year: dict[str, object] = field(default_factory=dict)
    all_invoices_dict_this_year: dict[str, object] = field(default_factory=dict)
    all_invoices_dict: dict[str, object] = field(default_factory=dict)

    total_costs_previous_year: float = 0.0
    total_costs_this_year: float = 0.0

    def get_all_invoices_dict_for_previous_year(self) -> dict:
        """Retrieve all invoices for the previous calendar year as a dictionary."""
        now_utc = datetime.now(UTC)
        now_local = now_utc.astimezone(LOCAL_TZ)
        previous_year = now_local.year - 1
        invoices_dict: dict[str, dict[str, object]] = {}

        for invoice in self.get_invoices_for_year(previous_year):
            period = invoice.PeriodDescription

            if period in invoices_dict:
                invoices_dict[period]["Total amount"] += invoice.TotalAmount
            else:
                invoices_dict[period] = {
                    "Start date": invoice.StartDate,
                    "Period description": period,
                    "Total amount": invoice.TotalAmount,
                }

        return invoices_dict

    def get_all_invoices_dict_for_this_year(self) -> dict:
        """Retrieve all invoices for the specified year as a dictionary."""
        now_utc = datetime.now(UTC)
        now_local = now_utc.astimezone(LOCAL_TZ)
        current_year = now_local.year
        invoices_dict: dict[str, dict[str, object]] = {}

        for invoice in self.get_invoices_for_year(current_year):
            period = invoice.PeriodDescription
            if period in invoices_dict:
                invoices_dict[period]["Total amount"] += invoice.TotalAmount
            else:
                invoices_dict[period] = {
                    "Start date": invoice.StartDate,
                    "Period description": period,
                    "Total amount": invoice.TotalAmount,
                }

        return invoices_dict

    def get_all_invoices_dict_per_year(self) -> dict[int, dict[str, object]]:
        """Calculate total invoice amounts per year."""
        all_invoices_dict: dict[int, dict[str, object]] = defaultdict(
            lambda: {
                "Start date": None,
                "Period description": None,
                "Total amount": 0.0,
            }
        )

        for invoice in self.all_periods_invoices:
            year = invoice.StartDate.year
            entry = all_invoices_dict[year]

            entry["Start date"] = invoice.StartDate
            entry["Period description"] = f"Total for {year}"
            entry["Total amount"] += invoice.TotalAmount

        return dict(all_invoices_dict)

    def get_all_invoices_dict(self) -> dict[str, dict[str, object]]:
        """Retrieve all invoices as a dictionary and sum duplicates."""
        invoices_dict: dict[str, dict[str, object]] = {}

        sorted_invoices = sorted(self.all_periods_invoices, key=lambda invoice: invoice.StartDate)

        for invoice in sorted_invoices:
            period = invoice.PeriodDescription

            if period in invoices_dict:
                invoices_dict[period]["Total amount"] += invoice.TotalAmount
            else:
                invoices_dict[period] = {
                    "Start date": invoice.StartDate,  # al lokaal
                    "Period description": period,
                    "Total amount": invoice.TotalAmount,
                }

        return invoices_dict

    def get_invoices_for_year(self, year: int) -> list[Invoice]:
        """Filter invoices based on the specified calendar year (Europe/Amsterdam)."""
        filtered_invoices = [invoice for invoice in self.all_periods_invoices if invoice.StartDate.year == year]

        filtered_invoices.sort(key=lambda invoice: invoice.StartDate)
        return filtered_invoices

    def calculate_total_costs(self, year: int) -> float:
        """Calculate the total costs for the specified year using all_periods_invoices."""
        return sum(invoice.TotalAmount for invoice in self.get_invoices_for_year(year))

    def calculate_average_costs_per_month(self, year: int = None) -> float | None:
        """Calculate the average costs per month."""
        invoices = self.all_periods_invoices if year is None else self.get_invoices_for_year(year)

        invoices_count = 0
        total_costs = 0.0
        unique_months = set()

        for invoice in invoices:
            # Set invoice to PeriodDescription
            invoice_month = invoice.PeriodDescription

            # Check if the month has already been counted
            # Do not count duplicate invoices and invoices with " tot " in the PeriodDescription
            if invoice_month not in unique_months and " tot " not in invoice_month:
                # ensure that we only count each month once.
                invoices_count += 1
                unique_months.add(invoice_month)

            total_costs += invoice.TotalAmount

        if invoices_count == 0:
            return None

        average_costs = total_costs / invoices_count

        return average_costs

    def calculate_expected_costs_this_year(self) -> float | None:
        """Calculate the expected costs for the current year."""
        current_year = datetime.now(UTC).year

        # Calculate the average costs per month for the current year
        average_costs_per_month = self.calculate_average_costs_per_month(year=current_year)

        if average_costs_per_month is None:
            return None

        # Multiply the average costs per month by 12 to get the expected costs for the year
        expected_costs_this_year = average_costs_per_month * 12

        return expected_costs_this_year

    def calculate_average_costs_per_year(self) -> float | None:
        """Calculate the average costs for the specified year."""
        invoices = self.all_periods_invoices

        if not invoices:
            return None

        total_costs = sum(invoice.TotalAmount for invoice in invoices)
        unique_years_count = len(self.get_unique_years())

        # Avoid division by zero
        if unique_years_count == 0:
            return None

        average_costs = total_costs / unique_years_count

        return average_costs

    def calculate_average_costs_per_month_this_year(self) -> float | None:
        """Calculate the average costs per month for this year."""
        invoices_count = 0
        total_costs = 0.0

        current_year = datetime.now(UTC).year

        for invoice in self.all_periods_invoices:
            if invoice.StartDate.year == current_year:
                if " tot " not in invoice.PeriodDescription:
                    invoices_count += 1
                    total_costs += invoice.TotalAmount
                else:
                    total_costs += invoice.TotalAmount

        if invoices_count == 0:
            return None

        current_month = datetime.now(UTC).month
        average_costs = total_costs / invoices_count

        if current_month == 1:
            # Handle January case, as it's the first month of the year
            average_costs *= 12
        else:
            average_costs *= 12 / current_month

        return average_costs

    def get_unique_years(self) -> set[int]:
        """Return unique years from invoices using local timezone."""
        return {
            self._to_local(start_date).year
            for invoice in self.all_periods_invoices
            if isinstance((start_date := getattr(invoice, "StartDate", None)), datetime)
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Invoices:
        """Parse the response from the invoices query."""
        _LOGGER.debug("Invoices response keys: %s", list(data.keys()))

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        payload = data.get("data", {}).get("invoices")
        if not isinstance(payload, dict):
            raise RequestException("Invalid invoices payload")

        instance = cls(
            all_periods_invoices=Invoice.from_list(payload.get("allInvoices", [])),
            previous_period_invoice=Invoice.from_dict(payload.get("previousPeriodInvoice")),
            current_period_invoice=Invoice.from_dict(payload.get("currentPeriodInvoice")),
            upcoming_period_invoice=Invoice.from_dict(payload.get("upcomingPeriodInvoice")),
        )

        current_year = datetime.now(UTC).year
        previous_year = current_year - 1

        instance.total_costs_previous_year = instance.calculate_total_costs(previous_year)
        instance.total_costs_this_year = instance.calculate_total_costs(current_year)
        instance.all_invoices_dict_previous_year = instance.get_all_invoices_dict_for_previous_year()
        instance.all_invoices_dict_this_year = instance.get_all_invoices_dict_for_this_year()
        instance.all_invoices_dict = instance.get_all_invoices_dict()
        return instance

    @classmethod
    def empty(cls) -> Invoices:
        """Return an empty Invoices object."""
        return cls(
            all_periods_invoices=[],
            previous_period_invoice=None,
            current_period_invoice=None,
            upcoming_period_invoice=None,
            all_invoices_dict_previous_year={},
            all_invoices_dict_this_year={},
            all_invoices_dict={},
            total_costs_previous_year=0.0,
            total_costs_this_year=0.0,
        )

    @staticmethod
    def _to_local(date_time: datetime) -> datetime:
        """Convert datetime to LOCAL_TZ."""
        if date_time.tzinfo is None:
            _LOGGER.debug("Naive datetime detected, assuming UTC: %s", date_time)
            date_time = date_time.replace(tzinfo=UTC)

        return date_time.astimezone(LOCAL_TZ)


@dataclass
class UsageItem:
    """Representeert een individueel gebruiksitem binnen een periode."""

    date: str
    from_time: str
    till_time: str
    usage: float
    costs: float
    unit: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> UsageItem:
        """Maakt een UsageItem-object aan vanuit een dictionary."""
        try:
            return UsageItem(
                date=str(data["date"]),
                from_time=str(data["from"]),
                till_time=str(data["till"]),
                usage=float(data["usage"]),
                costs=float(data["costs"]),
                unit=str(data["unit"]),
            )
        except KeyError as e:
            raise ValueError(f"Ontbrekend veld {e.args[0]} in UsageItem data: {data}") from e
        except (ValueError, TypeError) as e:
            raise ValueError(f"Fout bij conversie van UsageItem data: {e}, data: {data}") from e


@dataclass
class EnergyCategory:
    """Representeert een energiecategorie zoals gas, elektriciteit of teruglevering."""

    usage_total: float | None
    costs_total: float | None
    unit: str
    items: list[UsageItem]
    # costs_this_month: float = 0.0

    @staticmethod
    def from_dict(data: dict[str, Any]) -> EnergyCategory:
        """Create an EnergyCategory object from a dictionary."""
        _LOGGER.debug("EnergyCategory.from_dict() called with data: %s", data)
        try:
            if data is None:
                # return EnergyCategory(usage_total=0.00, costs_total=0.00, unit="", items=[])
                # TODO: Check if this is the correct behavior
                return None

            usage_val = data.get("usageTotal")
            usage_total = float(usage_val) if usage_val is not None else None

            costs_val = data.get("costsTotal")
            costs_total = float(costs_val) if costs_val is not None else None

            return EnergyCategory(
                usage_total=usage_total,
                costs_total=costs_total,
                unit=str(data["unit"]),
                items=[UsageItem.from_dict(item) for item in data.get("items", []) or []],
            )
        except KeyError as e:
            raise ValueError(f"Missing field {e.args[0]} in EnergyCategory data: {data}") from e
        except (ValueError, TypeError) as e:
            raise ValueError(f"Error converting EnergyCategory data: {e}, data: {data}") from e


@dataclass
class PeriodUsageAndCosts:
    """Bevat het verbruik en de kosten van gas, elektriciteit en teruglevering voor een periode."""

    _id: str
    gas: EnergyCategory | None
    electricity: EnergyCategory | None
    feed_in: EnergyCategory | None

    @staticmethod
    def from_dict(data: dict[str, object]) -> PeriodUsageAndCosts | None:
        """Parse usage and costs data."""
        try:
            input_data = data.get("data")
            if not isinstance(input_data, dict):
                raise RequestException("Missing 'data' in response")

            period_data = input_data.get("periodUsageAndCosts")
            if not isinstance(period_data, dict):
                return None

            # Handle cases where gas, electricity, or feed_in data is None
            gas_data = period_data.get("gas") if period_data.get("gas") is not None else None
            feed_in_data = period_data.get("feedIn") if period_data.get("feedIn") is not None else None
            electricity_data = period_data.get("electricity") if period_data.get("electricity") is not None else None

            # If any of the required data is missing, the field will be set to None
            return PeriodUsageAndCosts(
                _id=str(period_data["_id"]),
                gas=EnergyCategory.from_dict(gas_data) if gas_data else None,
                electricity=EnergyCategory.from_dict(electricity_data) if electricity_data else None,
                feed_in=EnergyCategory.from_dict(feed_in_data) if feed_in_data else None,
            )
        except KeyError as e:
            raise ValueError(f"Ontbrekend veld {e.args[0]} in PeriodUsageAndCosts data: {data}") from e
        except (ValueError, TypeError) as e:
            raise ValueError(f"Fout bij conversie van PeriodUsageAndCosts data: {e}, data: {data}") from e


@dataclass(slots=True)
class ContractPriceResolutionState:
    """State for price resolution settings."""

    active_option: str | None = None
    available_options: list[str] = field(default_factory=list)
    change_request_effective_date: date | str | None = None
    is_change_request_possible: bool = field(default=False)
    upcoming_change: date | str | None = None
    upcoming_change_effective_date: date | str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ContractPriceResolutionState:
        """Create an instance from raw API dictionary.
        Parse a dictionary into a ContractPriceResolutionState, converting dates."""

        return cls(
            active_option=data.get("activeOption"),
            available_options=data.get("availableOptions", []),
            change_request_effective_date=parse_date(data.get("changeRequestEffectiveDate")),
            is_change_request_possible=data.get("isChangeRequestPossible"),
            upcoming_change=data.get("upcomingChange"),
            upcoming_change_effective_date=parse_date(data.get("upcomingChangeEffectiveDate")),
        )

    # deprecated Backward-compatible aliases for camelCase properties
    @property
    def activeOption(self) -> str | None:
        """Backward compatibility alias."""
        return self.active_option

    @property
    def availableOptions(self) -> list[str]:
        """Backward compatibility alias."""
        return self.available_options

    @property
    def changeRequestEffectiveDate(self) -> date | str | None:
        """Backward compatibility alias."""
        return self.change_request_effective_date

    @property
    def isChangeRequestPossible(self) -> bool:
        """Backward compatibility alias."""
        return self.is_change_request_possible

    @property
    def upcomingChange(self) -> date | str | None:
        """Backward compatibility alias."""
        return self.upcoming_change

    @property
    def upcomingChangeEffectiveDate(self) -> date | str | None:
        """Backward compatibility alias."""
        return self.upcoming_change_effective_date


@dataclass
class UserSites:
    """UserSites data."""

    deliverySites: list[object]
    addressFormatted: str
    addressHasMultipleSites: bool
    deliveryEndDate: str | None
    deliveryStartDate: str | None
    firstMeterReadingDate: str | None
    lastMeterReadingDate: str | None
    propositionType: str | None
    reference: str
    segments: list[str]
    status: str

    @staticmethod
    def from_dict(data: dict[str, object]) -> UserSites:
        """Parse the response from the UserSites query."""
        _LOGGER.debug("UserSites %s", data)

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        if "errors" in data:
            raise RequestException(data["errors"][0]["message"])

        user_sites = data.get("data", {}).get("userSites")
        if not user_sites or not isinstance(user_sites, list):
            raise RequestException("Unexpected response format for userSites")

        first_meter_reading_date: str | None = None
        last_meter_reading_date: str | None = None
        if user_sites and isinstance(user_sites, list):
            first_site = user_sites[0]
            first_meter_reading_date = first_site.get("firstMeterReadingDate")
            last_meter_reading_date = first_site.get("lastMeterReadingDate")

        return UserSites(
            addressFormatted=first_site.get("addressFormatted"),
            addressHasMultipleSites=first_site.get("addressHasMultipleSites"),
            deliveryEndDate=first_site.get("deliveryEndDate"),
            deliveryStartDate=first_site.get("deliveryStartDate"),
            firstMeterReadingDate=first_meter_reading_date,
            lastMeterReadingDate=last_meter_reading_date,
            propositionType=first_site.get("propositionType"),
            reference=first_site.get("reference"),
            segments=first_site.get("segments"),
            status=first_site.get("status"),
            deliverySites=[DeliverySite.from_dict(site) for site in user_sites] if "DeliverySite" in globals() else [],
        )

    @property
    def format_delivery_site_as_dict(self) -> list[str]:
        """Format delivery site information as a list of formatted addresses."""
        sites_as_dict = []
        for site in self.deliverySites:
            address = getattr(site, "address", None)

            if address:
                sites_as_dict.append(
                    " ".join(
                        str(getattr(address, attr, "")).strip()
                        for attr in ["street", "houseNumber", "houseNumberAddition", "zipCode", "city"]
                        if getattr(address, attr, "")
                    )
                )
        return sites_as_dict


@dataclass
class InviteLink:
    """InviteLink data."""

    id: str
    from_name: str
    slug: str
    trees_amount_per_connection: int
    discount_per_connection: int

    @staticmethod
    def from_dict(data: dict[str, object]) -> InviteLink:
        """Parse the response from the InviteLink query."""
        _LOGGER.debug("InviteLink %s", data)

        if not data:
            return None

        errors = data.get("errors")
        if errors and isinstance(errors, list) and len(errors) > 0:
            message = errors[0].get("message") if isinstance(errors[0], dict) else "Unknown error"
            raise RequestException(message)

        if isinstance(data, dict) and "id" in data and "slug" in data:
            return InviteLink(
                id=data.get("id", ""),
                from_name=data.get("fromName", ""),
                slug=data.get("slug", ""),
                trees_amount_per_connection=data.get("treesAmountPerConnection", 0),
                discount_per_connection=data.get("discountPerConnection", 0),
            )

        # Try nested GraphQL style (Format B)
        root = None

        if isinstance(data, dict):
            root = data.get("data", {}).get("me", {}).get("InviteLinkUser")

        if not root:
            return None

        return InviteLink(
            id=str(root.get("id", "")),
            from_name=root.get("fromName", ""),
            slug=str(root.get("slug", "")),
            trees_amount_per_connection=root.get("treesAmountPerConnection", 0),
            discount_per_connection=root.get("discountPerConnection", 0),
        )

    @property
    def fromName(self) -> str:
        """Backward compatibility alias."""
        return self.from_name

    @property
    def discountPerConnection(self) -> int:
        """Backward compatibility alias."""
        return self.discount_per_connection

    @property
    def treesAmountPerConnection(self) -> int:
        """Backward compatibility alias."""
        return self.trees_amount_per_connection


@dataclass
class PushNotificationPriceAlert:
    """Push notification price alert data."""

    id: str
    is_enabled: bool
    type: str
    weekdays: list[int]

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PushNotificationPriceAlert | None:
        """Create a PushNotificationPriceAlert from a dictionary."""

        if not isinstance(data, dict):
            return None

        return cls(
            id=str(data.get("id")),
            is_enabled=bool(data.get("isEnabled")),
            type=str(data.get("type")),
            weekdays=list(data.get("weekdays", [])),
        )

    @staticmethod
    def from_response(data: dict[str, object]) -> list[PushNotificationPriceAlert]:
        """Parse the GraphQL response from the PushNotificationPriceAlerts query."""
        _LOGGER.debug("Parsing PushNotificationPriceAlerts response: %s", data)

        if "errors" in data:
            error_msg = data["errors"][0].get("message", "Unknown error")
            raise RequestException(error_msg)

        payload = data.get("data", {}).get("me", {}).get("PushNotificationPriceAlerts")

        if not payload or not isinstance(payload, list):
            raise RequestException("Unexpected or missing PushNotificationPriceAlerts data")

        alerts = [PushNotificationPriceAlert.from_dict(alert) for alert in payload]
        _LOGGER.debug("Parsed %d PushNotificationPriceAlerts", len(alerts))

        return alerts


@dataclass
class Me:
    """Me data, including the current status of the connection."""

    id: str
    email: str
    countryCode: str
    advancedPaymentAmount: float
    treesCount: int
    hasInviteLink: bool
    InviteLinkUser: InviteLink | None
    hasCO2Compensation: bool
    createdAt: str
    updatedAt: str
    addressHasMultipleSites: bool
    meterReadingExportPeriods: list[MeterReadingExportPeriod]
    smartCharging: dict[str, object]
    PushNotificationPriceAlerts: list[PushNotificationPriceAlert] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> Me:
        """Parse the response from the me query."""
        _LOGGER.debug("User payload received: %s", data)

        errors = data.get("errors")
        if errors:
            message = getattr(errors[0], "get", lambda k, d=None: "Unknown error")("message")
            raise RequestException(message)

        raw_data = data.get("data")
        if not isinstance(raw_data, dict):
            raise RequestException("Missing 'data' in response")

        payload = raw_data.get("me")
        if not payload:
            raise RequestException("Unexpected response")

        invite_link_user = None
        if payload.get("InviteLinkUser"):
            invite_link_user = InviteLink.from_dict(payload["InviteLinkUser"])

        push_notification_price_alerts = [
            PushNotificationPriceAlert.from_dict(alert)
            for alert in payload.get("PushNotificationPriceAlerts", [])
            if isinstance(alert, dict)
        ]

        meter_periods = [
            MeterReadingExportPeriod.from_dict(period)
            for period in payload.get("meterReadingExportPeriods", [])
            if isinstance(period, dict)
        ]

        return Me(
            id=payload.get("id", ""),
            email=payload.get("email", ""),
            countryCode=payload.get("countryCode", ""),
            advancedPaymentAmount=payload.get("advancedPaymentAmount", 0.0),
            treesCount=payload.get("treesCount", 0),
            hasInviteLink=payload.get("hasInviteLink", False),
            InviteLinkUser=invite_link_user,
            PushNotificationPriceAlerts=push_notification_price_alerts,
            hasCO2Compensation=payload.get("hasCO2Compensation"),
            createdAt=payload.get("createdAt"),
            updatedAt=payload.get("updatedAt"),
            addressHasMultipleSites=payload.get("addressHasMultipleSites"),
            meterReadingExportPeriods=meter_periods,
            smartCharging=payload.get("smartCharging") or {},
        )


def get_segments(data: dict[str, Any]) -> list[str] | None:
    delivery_site_data = data.get("user")
    if delivery_site_data:
        delivery_site = DeliverySite(**delivery_site_data)
        return delivery_site.segments
    return None


@dataclass
class Address:
    """Address of the delivery site."""

    street: str
    houseNumber: str
    zipCode: str
    city: str
    houseNumberAddition: str | None = field(default=None)

    @staticmethod
    def from_dict(data: dict[str, object]) -> Address | None:
        """Create Address from API response dict.

        Args:
            data: Raw API response.

        Returns:
            Address instance or None if invalid input.
        """
        address_formatted = data.get("addressFormatted")

        if not isinstance(address_formatted, list) or len(address_formatted) < 2:
            _LOGGER.debug(
                "Invalid addressFormatted: %s",
                address_formatted,
            )
            return None

        street_and_number = str(address_formatted[0]).strip()
        postcode_and_city = str(address_formatted[1]).strip()

        street, house_number, house_number_addition = Address._parse_street_and_number(street_and_number)
        zip_code, city = Address._parse_zip_and_city(postcode_and_city)

        return Address(
            street=street,
            houseNumber=house_number,
            zipCode=zip_code,
            city=city,
            houseNumberAddition=house_number_addition,
        )

    @staticmethod
    def _parse_street_and_number(value: str) -> tuple[str, str, str | None]:
        """Parse 'Street 123A' into components."""
        if not value:
            return "", "", None

        parts = value.rsplit(" ", 1)
        street = parts[0]
        house_number_raw = parts[1] if len(parts) > 1 else ""

        number = ""
        addition = None

        for index, char in enumerate(house_number_raw):
            if char.isalpha():
                number = house_number_raw[:index]
                addition = house_number_raw[index:]
                break
        else:
            number = house_number_raw

        return street, number, addition

    @staticmethod
    def _parse_zip_and_city(value: str) -> tuple[str, str]:
        """Parse postcode and city safely."""
        if not value:
            return "", ""

        parts = value.split()

        # Dutch format: "1234 AB City"
        if len(parts) >= 3 and parts[0].isdigit():
            zip_code = f"{parts[0]} {parts[1]}"
            city = " ".join(parts[2:])
            return zip_code, city

        # Belgian format: "1000 City"
        if len(parts) >= 2 and parts[0].isdigit():
            zip_code = parts[0]
            city = " ".join(parts[1:])
            return zip_code, city

        _LOGGER.debug("Unexpected postcode/city format: %s", value)
        return value, ""


# @dataclass
class DeliverySite(BaseModel):
    """Delivery sites data, including the address and delivery status.

    {
        "reference": "1082MK 10",
        "segments": [
            "ELECTRICITY",
            "GAS"
        ],
        "address": {
            "street": "Gustav Mahlerlaan",
            "houseNumber": "1025",
            "houseNumberAddition": null,
            "zipCode": "1082 MK",
            "city": "AMSTERDAM"
        },
        "addressHasMultipleSites": false,
        "status": "DELIVERY_ENDED",
        "propositionType": null,
        "deliveryStartDate": "2023-01-05",
        "deliveryEndDate": "2024-02-09",
        "firstMeterReadingDate": "2023-01-05",
        "lastMeterReadingDate": "2024-02-08"
    },
    """

    addressHasMultipleSites: bool
    propositionType: str | None
    reference: str
    segments: list[str]
    address: Address
    status: str
    deliveryStartDate: date | None
    deliveryEndDate: date | None = None
    firstMeterReadingDate: date | None
    lastMeterReadingDate: date | None

    @staticmethod
    def from_dict(payload: dict[str, str]) -> DeliverySite:
        """Parse the response from the me query."""

        if not payload:
            return None

        _LOGGER.debug("DeliverySites %s", payload)

        address_data = payload.get("address")
        address = Address.from_dict(address_data) if address_data else None

        return (
            DeliverySite(
                reference=payload.get("reference"),
                segments=payload.get("segments", []),
                addressHasMultipleSites=payload.get("addressHasMultipleSites", False),
                address=address,
                propositionType=payload.get("propositionType"),
                status=payload.get("status"),
                deliveryStartDate=(
                    datetime.strptime(payload.get("deliveryStartDate"), "%Y-%m-%d").date()
                    if payload.get("deliveryStartDate")
                    else None
                ),
                deliveryEndDate=(
                    datetime.strptime(payload.get("deliveryEndDate"), "%Y-%m-%d").date()
                    if payload.get("deliveryEndDate")
                    else None
                ),
                firstMeterReadingDate=(
                    datetime.strptime(payload.get("firstMeterReadingDate"), "%Y-%m-%d").date()
                    if payload.get("firstMeterReadingDate")
                    else None
                ),
                lastMeterReadingDate=(
                    datetime.strptime(payload.get("lastMeterReadingDate"), "%Y-%m-%d").date()
                    if payload.get("lastMeterReadingDate")
                    else None
                ),
            )
            if payload
            else None
        )

    @property
    def format_delivery_site_as_dict(self):
        sites_as_dict = []
        for site in self.deliverySites:
            address = site.get("address", {})
            sites_as_dict.append(
                f"{address.get('street')} {address.get('houseNumber')} {address.get('houseNumberAddition', '') if address.get('houseNumberAddition') else ''} {address.get('zipCode')} {address.get('city')}"
            )
        return sites_as_dict


@dataclass
class Person:
    """Represents a person."""

    firstName: str | None = None
    lastName: str | None = None

    @staticmethod
    def from_dict(data: dict[str, object]) -> Person:
        """Create Person from API response.

        Args:
            data: Raw API data.

        Returns:
            Person instance.
        """
        if not isinstance(data, dict):
            _LOGGER.debug("Invalid data for Person: %s", data)
            return Person()

        first_name = data.get("firstName")
        last_name = data.get("lastName")

        return Person(
            firstName=first_name if isinstance(first_name, str) else None,
            lastName=last_name if isinstance(last_name, str) else None,
        )


@dataclass
class Contact:
    emailAddress: EmailStr | None = None
    phoneNumber: str | None = None
    mobileNumber: str | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Contact:
        return Contact(
            emailAddress=data.get("emailAddress"),
            phoneNumber=data.get("phoneNumber"),
            mobileNumber=data.get("mobileNumber"),
        )


@dataclass
class Email:
    email: EmailStr


@dataclass
class Debtor:
    bankAccountNumber: str | None = None
    preferredAutomaticCollectionDay: int | None = None

    @staticmethod
    def from_dict(data: dict[str, object]) -> Debtor:
        return Debtor(
            bankAccountNumber=data.get("bankAccountNumber"),
            preferredAutomaticCollectionDay=data.get("preferredAutomaticCollectionDay"),
        )


@dataclass
class GridOperatorAddress(DictLikeMixin):
    """Address of the grid operator."""

    street: str | None = None
    houseNumber: str | None = None
    houseNumberAddition: str | None = None
    zipCode: str | None = None
    city: str | None = None

    @staticmethod
    def from_dict(data: dict[str, object]) -> GridOperatorAddress:
        return GridOperatorAddress(
            street=data.get("street"),
            houseNumber=data.get("houseNumber"),
            houseNumberAddition=data.get("houseNumberAddition"),
            zipCode=data.get("zipCode"),
            city=data.get("city"),
        )


@dataclass
class Contract(DictLikeMixin):
    startDate: datetime | None
    endDate: datetime | None
    contractType: str | None
    productName: str | None
    tariffChartId: str | None

    @staticmethod
    def from_dict(data: dict[str, object]) -> Contract | None:
        if not data:
            return None

        start_date = _parse_iso_datetime(data.get("startDate"), "startDate")
        end_date = _parse_iso_datetime(data.get("endDate"), "endDate")

        return Contract(
            startDate=start_date,
            endDate=end_date,
            contractType=data.get("contractType"),
            productName=data.get("productName"),
            tariffChartId=data.get("tariffChartId"),
        )


@dataclass
class ConnectionExternalDetails(DictLikeMixin):
    """Grid-operator details nested inside a ``Connection`` object.

    Maps to the ``externalDetails`` field returned by the
    ``connections { externalDetails { ... } }`` GraphQL fragment::

        externalDetails {
            gridOperator
            address { street houseNumber houseNumberAddition zipCode city }
            contract { startDate endDate contractType productName tariffChartId }
        }
    """

    grid_operator: str | None = None
    address: GridOperatorAddress = field(default_factory=GridOperatorAddress)
    contract: Contract | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ConnectionExternalDetails:
        """Parse a raw ``externalDetails`` dict from the API."""
        if not data:
            return ConnectionExternalDetails()
        return ConnectionExternalDetails(
            grid_operator=data.get("gridOperator"),
            address=GridOperatorAddress.from_dict(data.get("address") or {}),
            contract=Contract.from_dict(data.get("contract") or {}),
        )


@dataclass
class Connection(DictLikeMixin):
    """Represents a connection to the energy grid."""

    id: str | None = None
    connectionId: str | None = None
    EAN: str | None = None
    segment: str | None = None
    status: str | None = None
    contractStatus: str | None = None
    estimatedFeedIn: float | None = None
    firstMeterReadingDate: str | None = None
    lastMeterReadingDate: str | None = None
    meterType: str | None = None
    externalDetails: ConnectionExternalDetails = field(default_factory=ConnectionExternalDetails)
    contract: Contract | None = None

    @staticmethod
    def from_dict(data: dict[str, object]) -> Connection:
        return Connection(
            id=data.get("id"),
            connectionId=data.get("connectionId"),
            EAN=data.get("EAN"),
            segment=data.get("segment"),
            status=data.get("status"),
            contractStatus=data.get("contractStatus"),
            estimatedFeedIn=data.get("estimatedFeedIn"),
            firstMeterReadingDate=data.get("firstMeterReadingDate"),
            lastMeterReadingDate=data.get("lastMeterReadingDate"),
            meterType=data.get("meterType"),
            externalDetails=ConnectionExternalDetails.from_dict(data.get("externalDetails", {})),
            contract=Contract.from_dict(data.get("contract", {})),
        )


@dataclass
class UserExternalDetails:
    """Account-level details nested directly on a ``User`` / ``Me`` object.

    Maps to the top-level ``externalDetails`` field returned by the
    ``me { externalDetails { ... } }`` GraphQL fragment::

        externalDetails {
            reference
            person    { firstName lastName }
            contact   { emailAddress phoneNumber mobileNumber }
            address   { street houseNumber houseNumberAddition zipCode city }
            debtor    { bankAccountNumber preferredAutomaticCollectionDay }
        }
    """

    reference: str | None = None
    person: Person | None = None
    contact: Contact | None = None
    address: Address | None = None
    debtor: Debtor | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> UserExternalDetails:
        """Parse a raw ``externalDetails`` dict from the API."""
        if not data:
            return UserExternalDetails()
        return UserExternalDetails(
            reference=data.get("reference"),
            person=Person.from_dict(data.get("person") or {}),
            contact=Contact.from_dict(data.get("contact") or {}),
            address=Address.from_dict(data.get("address") or {}),
            debtor=Debtor.from_dict(data.get("debtor") or {}),
        )


@dataclass
class MeterReadingExportPeriod:
    EAN: str
    # user: 'User'
    cluster: str
    # createdAt: str
    from_date: str
    till_date: str
    period: str
    segment: str
    type: str
    # updatedAt: str

    @staticmethod
    def from_dict(data: dict[str, object]) -> MeterReadingExportPeriod:
        return MeterReadingExportPeriod(
            EAN=data.get("EAN"),
            # user=data.get("user"),
            cluster=data.get("cluster"),
            # createdAt=data.get("createdAt"),
            from_date=data.get("from"),
            till_date=data.get("till"),
            period=data.get("period"),
            segment=data.get("segment"),
            type=data.get("type"),
            # updatedAt=data.get("updatedAt"),
        )


@dataclass
class UserDetails:
    id: str | None = None
    email: str | None = None


@dataclass
class Signup:
    user: UserDetails


@dataclass
class UserSettings:
    id: str
    disabledHapticFeedback: bool
    jedlixUserId: str | None
    jedlixPushNotifications: bool
    smartPushNotifications: bool
    rewardPayoutPreference: str


@dataclass
class activePaymentAuthorization:
    """Represents an active payment authorization record."""

    id: str
    mandateId: str
    signedAt: str
    bankAccountNumber: str
    status: str

    @staticmethod
    def from_dict(data: dict) -> activePaymentAuthorization:
        return activePaymentAuthorization(
            id=data.get("id"),
            mandateId=data.get("mandateId"),
            signedAt=data.get("signedAt"),
            bankAccountNumber=data.get("bankAccountNumber"),
            status=data.get("status"),
        )


@dataclass
class InviteLinkUser:
    awardRewardType: str
    createdAt: str
    description: str | None
    discountPerConnection: int
    fromName: str
    id: str
    imageUrl: str | None
    slug: str
    status: str
    tintColor: str | None
    treesAmountPerConnection: int
    type: str
    updatedAt: str
    usedCount: int


@dataclass
class Organization:
    Email: str


@dataclass
class SmartCharging:
    isActivated: bool | None = None
    provider: str | None = None
    userCreatedAt: str | None = None
    userId: str | None = None
    isAvailableInCountry: bool | None = None
    needsSubscription: bool | None = None
    subscription: str | None = None


@dataclass
class SmartTrading:
    isActivated: bool | None = None
    userCreatedAt: str | None = None
    userId: str | None = None
    isAvailableInCountry: bool | None = None


@dataclass
class SmartHvac:
    isActivated: bool | None = None
    userCreatedAt: str | None = None
    userId: str | None = None
    isAvailableInCountry: bool | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> SmartHvac | None:
        """Parse SmartHvac from dictionary."""
        if not data:
            return None
        return cls(
            isActivated=data.get("isActivated"),
            userCreatedAt=data.get("userCreatedAt"),
            userId=data.get("userId"),
            isAvailableInCountry=data.get("isAvailableInCountry"),
        )


@dataclass
class ExternalDetails:
    reference: str | None = None
    person: Person | None = None
    contact: Contact | None = None
    address: Address | None = None
    debtor: Debtor | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ExternalDetails:
        return ExternalDetails(
            reference=data.get("reference"),
            person=Person.from_dict(data.get("person", {})),
            contact=Contact.from_dict(data.get("contact", {})),
            address=Address.from_dict(data.get("address", {})),
            debtor=Debtor.from_dict(data.get("debtor", {})),
        )


@dataclass
class DeliverySiteFormat:
    """Formatted address of the delivery site."""

    address: Address

    def formatted_info(self) -> str:
        """Return formatted address of the delivery site."""
        return f"{self.address.street} {self.address.houseNumber} {self.address.zipCode} {self.address.city}"


@dataclass
class DeliverySiteList:
    """List with delivery sites."""

    delivery_sites: list[DeliverySite]

    def __iter__(self):
        """Return an iterator over the delivery sites."""
        return iter(self.delivery_sites)

    def as_list(self) -> list[dict[str, str]]:
        """Convert the delivery sites to a list of dictionaries.

        Each dictionary represents the formatted information of a delivery site.

        Returns:
            A list of dictionaries representing the delivery sites.
        """
        sites = []
        for index, site in enumerate(self.delivery_sites, start=1):
            site_name = f"Delivery site {index}"
            site_info = {site_name: site.formatted_info()}
            sites.append(site_info)
        return sites

    def as_dict(self) -> dict[str, dict]:
        """Convert the delivery sites to a dictionary of address information.

        Each key-value pair represents the site name and the corresponding address
        information of a delivery site.

        Returns:
            A dictionary where keys are site names and values are address information dictionaries.
        """
        site_dict = {}
        for index, site in enumerate(self.delivery_sites, start=1):
            site_name = f"Delivery site {index}"
            site_dict[site_name] = site.address.__dict__
        return site_dict


@dataclass
class DailyConsumption:
    def __init__(self, date: str, consumption_kwh: float):
        """
        Initialize a DailyConsumption instance.

        Parameters:
        - date (str): The date of the daily consumption.
        - consumption_kwh (float): The energy consumption in kilowatt-hours for the specified date.
        """
        self.date = date
        self.consumption_kwh = consumption_kwh


@dataclass
class EnergyConsumption:
    def __init__(self, user_id: str, daily_consumption: list[DailyConsumption]):
        """
        Initialize an EnergyConsumption instance.

        Parameters:
        - user_id (str): The unique identifier of the user.
        - daily_consumption (List[DailyConsumption]): A list of DailyConsumption instances representing daily energy consumption.
        """
        self.user_id = user_id
        self.daily_consumption = daily_consumption

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnergyConsumption | None:
        """
        Create an EnergyConsumption instance from a dictionary.

        Parameters:
        - data (Dict[str, Any]): The input dictionary containing user and energy consumption data.

        Returns:
        - EnergyConsumption: An instance of the EnergyConsumption class.
        """
        user_data = data.get("user", {})
        user_id = user_data.get("id")
        daily_consumption_data = user_data.get("energyConsumption", {}).get("daily", [])

        daily_consumption = [
            DailyConsumption(date=item.get("date"), consumption_kwh=item.get("consumptionKwh"))
            for item in daily_consumption_data
        ]

        return cls(user_id, daily_consumption)


@dataclass
class User:
    """User data, including the current status of the connection."""

    id: str
    PaymentAuthorizations: list
    activePaymentAuthorization: list | None
    InviteLinkUser: InviteLinkUser
    Organization: Organization
    # deliverySites: DeliverySiteList
    connections: list[Connection]
    # deliverySites: list[DeliverySite]
    createdAt: datetime | None
    updatedAt: datetime | None
    email: str
    # firstName: Optional[str]
    # lastName: Optional[str]
    countryCode: str
    # segments: list[str]
    lastLogin: datetime
    reference: int
    connectionsStatus: str
    # deliveryStartDate: date
    # firstMeterReadingDate: date
    # lastMeterReadingDate: date
    meterReadingExportPeriods: dict[str, object]
    advancedPaymentAmount: float
    hasCO2Compensation: bool
    hasInviteLink: bool
    status: str
    UserSettings: dict[str, object]
    PushNotificationPriceAlerts: list[object]
    # propositionType: str
    websiteUrl: str
    customerSupportEmail: str
    Signup: Signup
    treesCount: int | None = 0
    friendsCount: int | None = 0
    smartCharging: SmartCharging | None = None
    smartTrading: SmartTrading | None = None
    smartHvac: SmartHvac | None = None
    externalDetails: UserExternalDetails = field(default_factory=UserExternalDetails)
    deliveryEndDate: date | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> User | None:
        """Parse the response from the me query."""
        _LOGGER.debug("User %s", data)

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        payload = data.get("data", {}).get("me")
        if payload is None:
            raise RequestException("Unexpected response")

        _LOGGER.debug("deliverySites %s", payload.get("deliverySites"))

        last_login = _parse_iso_datetime(payload.get("lastLogin"), "lastLogin")
        created_at = _parse_iso_datetime(payload.get("createdAt"), "createdAt")
        updated_at = _parse_iso_datetime(payload.get("updatedAt"), "updatedAt")

        return User(
            id=payload.get("id"),
            InviteLinkUser=payload.get("InviteLinkUser"),
            Signup=payload.get("Signup"),
            Organization=payload.get("Organization"),
            PaymentAuthorizations=payload.get("PaymentAuthorizations"),
            activePaymentAuthorization=payload.get("activePaymentAuthorization"),
            countryCode=payload.get("countryCode"),
            # segments=first_site.get("segments", []),
            # lastLogin=datetime.fromisoformat(payload.get("lastLogin")),
            lastLogin=last_login,
            createdAt=created_at,
            updatedAt=updated_at,
            email=payload.get("email"),
            reference=payload.get("reference"),
            connectionsStatus=payload.get("connectionsStatus"),
            # firstMeterReadingDate=payload.get("deliverySites")[
            #     0].get("firstMeterReadingDate"),
            # lastMeterReadingDate=payload.get("deliverySites")[
            #     0].get("lastMeterReadingDate"),
            # deliveryStartDate=first_site.get("deliveryStartDate"),
            # deliveryEndDate=first_site.get("deliveryEndDate"),
            # firstMeterReadingDate=first_site.get("firstMeterReadingDate"),
            # lastMeterReadingDate=first_site.get("lastMeterReadingDate"),
            meterReadingExportPeriods=payload.get("meterReadingExportPeriods", {}),
            advancedPaymentAmount=payload.get("advancedPaymentAmount"),
            hasInviteLink=payload.get("hasInviteLink", False),
            hasCO2Compensation=payload.get("hasCO2Compensation", False),
            treesCount=payload.get("treesCount", 0),
            friendsCount=payload.get("friendsCount", 0),
            status=payload.get("status"),
            websiteUrl=payload.get("websiteUrl"),
            customerSupportEmail=payload.get("customerSupportEmail"),
            UserSettings=payload.get("UserSettings", {}),
            PushNotificationPriceAlerts=payload.get("PushNotificationPriceAlerts", []),
            # propositionType=payload.get("deliverySites")[
            #     0].get("propositionType"),
            # smartCharging=payload.get("deliverySites")[
            #     0].get("smartCharging"),
            # propositionType=first_site.get("propositionType"),
            smartCharging=payload.get("smartCharging", {}),
            smartTrading=payload.get("smartTrading", {}),
            smartHvac=SmartHvac.from_dict(payload.get("smartHvac")),
            connections=[Connection.from_dict(c) for c in payload.get("connections") or [] if isinstance(c, dict)],
            externalDetails=UserExternalDetails.from_dict(payload.get("externalDetails", {})),
        )

    # verwijder dit is verplaatst naar de deliverysite class
    @property
    def old_format_delivery_site_as_dict(self):
        sites_as_dict = []
        for site in self.deliverySites:
            address = site.get("address", {})
            sites_as_dict.append(
                f"{address.get('street')} {address.get('houseNumber')} {address.get('houseNumberAddition', '') if address.get('houseNumberAddition') else ''} {address.get('zipCode')} {address.get('city')}"
            )
        return sites_as_dict

    @property
    def delivery_site_as_list(self):
        sites = []
        for index, site in enumerate(self.deliverySites, start=1):
            address = site.get("address", {})
            site_name = f"Delivery site {index}"
            house_number_addition = (
                f"{address.get('houseNumberAddition')}" if address.get("houseNumberAddition") else ""
            )
            site_info = {
                site_name: f"{address.get('street')} {address.get('houseNumber')} {house_number_addition if house_number_addition else ''} {address.get('zipCode')} {address.get('city')}"
            }
            sites.append(site_info)
        return sites

    @property
    def delivery_site_as_dict(self):
        site_dict = {}
        for index, site in enumerate(self.deliverySites, start=1):
            address = site.get("address", {})
            site_name = f"Delivery site {index}"
            site_info = {
                "street": address.get("street"),
                "house_number": address.get("houseNumber"),
                "zip_code": address.get("zipCode"),
                "city": address.get("city"),
            }
            if address.get("houseNumberAddition"):
                site_info["house_number_addition"] = address.get("houseNumberAddition", "")
            site_dict[site_name] = site_info
        return site_dict

    @property
    def delivery_sites(self) -> dict[str, dict]:
        site_dict = {}
        for index, site in enumerate(self.deliverySites, start=1):
            address = site.get("address", {})
            site_name = f"Delivery site {index}"
            site_info = {
                f"{address.get('street')} {address.get('houseNumber')} {address.get('houseNumberAddition', '') if address.get('houseNumberAddition') else ''} {address.get('zipCode')} {address.get('city')}"
            }
            site_dict[site_name] = site_info
        return site_dict


@dataclass
class Difference:
    """Difference block for gas, electricity, or feed-in."""

    actualUsage: float
    actualAverageUnitPrice: float
    actualCosts: float
    expectedUsage: float
    expectedAverageUnitPrice: float
    expectedCosts: float
    unit: str

    @staticmethod
    def from_dict(data: dict) -> Difference:
        return Difference(
            actualUsage=float(data.get("actualUsage", 0.0)),
            actualAverageUnitPrice=float(data.get("actualAverageUnitPrice", 0.0)),
            actualCosts=float(data.get("actualCosts", 0.0)),
            expectedUsage=float(data.get("expectedUsage", 0.0)),
            expectedAverageUnitPrice=float(data.get("expectedAverageUnitPrice", 0.0)),
            expectedCosts=float(data.get("expectedCosts", 0.0)),
            unit=str(data.get("unit", "")),
        )


@dataclass
class MonthInsights:
    """Month summary including expected and actual costs and usage differences."""

    _id: str
    expectedCosts: float
    expectedCostsGas: float
    expectedCostsFixed: float
    expectedCostsElectricity: float
    expectedCostsFeedIn: float
    expectedCostsUntilLastMeterReading: float
    actualCostsUntilLastMeterReading: float
    lastMeterReadingDate: datetime
    invoiceId: str | None
    gasDifference: Difference
    electricityDifference: Difference
    feedInDifference: Difference
    meterReadingDayCompleteness: float
    gasExcluded: bool

    def __post_init__(self) -> None:
        """Ensure datetime is timezone-aware."""
        if self.lastMeterReadingDate.tzinfo is None:
            self.lastMeterReadingDate = self.lastMeterReadingDate.replace(tzinfo=UTC)

    @staticmethod
    def from_dict(data: dict[str, str]) -> MonthInsights | None:
        """Parse the response from the monthSummary query."""
        _LOGGER.debug("MonthInsights %s", data)

        if data is None:
            return None

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        payload = data.get("data", {}).get("monthInsights")
        if payload is None:
            raise RequestException("Unexpected response")
        _LOGGER.debug("MonthInsights %s", payload)

        # Parse ISO8601 with timezone handling
        last_date_raw = payload.get("lastMeterReadingDate")
        try:
            dt = datetime.fromisoformat(last_date_raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
        except Exception as exc:
            raise ValueError("Invalid lastMeterReadingDate format.") from exc

        return MonthInsights(
            _id=str(data.get("_id", "")),
            expectedCosts=float(data.get("expectedCosts", 0.0)),
            expectedCostsGas=float(data.get("expectedCostsGas", 0.0)),
            expectedCostsFixed=float(data.get("expectedCostsFixed", 0.0)),
            expectedCostsElectricity=float(data.get("expectedCostsElectricity", 0.0)),
            expectedCostsFeedIn=float(data.get("expectedCostsFeedIn", 0.0)),
            expectedCostsUntilLastMeterReading=float(data.get("expectedCostsUntilLastMeterReading", 0.0)),
            actualCostsUntilLastMeterReading=float(data.get("actualCostsUntilLastMeterReading", 0.0)),
            lastMeterReadingDate=dt,
            invoiceId=data.get("invoiceId"),
            gasDifference=Difference.from_dict(data.get("gasDifference", {})),
            electricityDifference=Difference.from_dict(data.get("electricityDifference", {})),
            feedInDifference=Difference.from_dict(data.get("feedInDifference", {})),
            meterReadingDayCompleteness=float(data.get("meterReadingDayCompleteness", 0.0)),
            gasExcluded=bool(data.get("gasExcluded", False)),
        )


@dataclass(slots=True)
class MonthSummary:
    """Month summary data, including the actual and expected costs for this month."""

    _id: str
    actualCostsUntilLastMeterReadingDate: float
    expectedCostsUntilLastMeterReadingDate: float
    lastMeterReadingDate: str
    costs_per_day_till_now: float
    meterReadingDayCompleteness: float
    gasExcluded: bool
    typename: str
    expectedCosts: float | None = None
    expectedCostsPerDay: float | None = None

    @staticmethod
    def old_from_dict(data: Mapping[str, object]) -> MonthSummary | None:
        """Parse the response from the monthSummary query.

        Returns ``None`` when Frank Energie has no summary to deliver yet
        (absent payload, empty payload, ``data.monthSummary: null``). This is
        a normal transient state — typically the first few days of a new
        billing month, before the previous month's invoice is generated.

        Only raises when the FE response is *malformed-but-present*: schema
        drift, mixed-type fields on a populated summary, etc.
        """
        _LOGGER.debug("MonthSummary model %s", data)

        if data is None:
            return None

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        root = data.get("data", {})

        if not isinstance(root, dict):
            raise RequestException("Unexpected response format")

        payload = root.get("monthSummary")

        if payload is None:
            return None

        if not isinstance(payload, Mapping):
            raise RequestException("Unexpected monthSummary payload type")

        expected_costs = payload.get("expectedCosts")
        last_reading = payload.get("lastMeterReadingDate")
        actual_costs = payload.get("actualCostsUntilLastMeterReadingDate")

        if expected_costs is None and last_reading is None and actual_costs is None:
            return None

        if not isinstance(expected_costs, (int, float, type(None))):
            raise RequestException("Invalid expectedCosts")

        if not isinstance(actual_costs, (int, float)):
            raise RequestException("Invalid actualCostsUntilLastMeterReadingDate")

        if not isinstance(last_reading, str):
            raise RequestException("Invalid lastMeterReadingDate")

        if expected_costs is not None:
            expected_costs_per_day = MonthSummary.calculate_expected_costs_per_day(expected_costs, last_reading)
        else:
            expected_costs_per_day = None

        costs_per_day_till_now = MonthSummary.calculate_costs_per_day_till_now(actual_costs, last_reading)

        return MonthSummary(
            _id=payload.get("_id"),
            actualCostsUntilLastMeterReadingDate=actual_costs,
            expectedCostsUntilLastMeterReadingDate=payload.get("expectedCostsUntilLastMeterReadingDate"),
            expectedCosts=expected_costs,
            expectedCostsPerDay=expected_costs_per_day,
            costs_per_day_till_now=costs_per_day_till_now,
            lastMeterReadingDate=last_reading,
            meterReadingDayCompleteness=payload.get("meterReadingDayCompleteness"),
            gasExcluded=payload.get("gasExcluded"),
            typename=payload.get("__typename"),
        )

    @staticmethod
    def from_dict(
        data: Mapping[str, object] | None,
    ) -> MonthSummary | None:
        """Parse the response from the monthSummary query.

        Returns ``None`` when Frank Energie has no summary to deliver yet
        (absent payload, empty payload, ``data.monthSummary: null``). This is
        a normal transient state — typically the first few days of a new
        billing month, before the previous month's invoice is generated.

        Only raises when the FE response is malformed-but-present.
        """
        _LOGGER.debug("MonthSummary model %s", data)

        if data is None:
            return None

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        root = data.get("data")

        if not isinstance(root, Mapping):
            raise RequestException("Missing data payload")

        payload = root.get("monthSummary")

        if payload is None:
            return None

        if not isinstance(payload, Mapping):
            raise RequestException("Unexpected monthSummary payload type")

        summary_id = payload.get("_id")
        actual_costs = payload.get("actualCostsUntilLastMeterReadingDate")
        expected_costs = payload.get("expectedCosts")
        expected_costs_until = payload.get("expectedCostsUntilLastMeterReadingDate")
        last_reading = payload.get("lastMeterReadingDate")
        completeness = payload.get("meterReadingDayCompleteness")
        gas_excluded = payload.get("gasExcluded")
        typename = payload.get("__typename")

        if expected_costs is None and last_reading is None and actual_costs is None:
            return None

        if not isinstance(summary_id, str):
            raise RequestException("Invalid _id")

        if not isinstance(actual_costs, (int, float)):
            raise RequestException("Invalid actualCostsUntilLastMeterReadingDate")

        if not isinstance(last_reading, str):
            raise RequestException("Invalid lastMeterReadingDate")

        if not isinstance(
            expected_costs_until,
            (int, float),
        ):
            raise RequestException("Invalid expectedCostsUntilLastMeterReadingDate")

        if not isinstance(expected_costs, (int, float, type(None))):
            raise RequestException("Invalid expectedCosts")

        if not isinstance(completeness, (int, float)):
            raise RequestException("Invalid meterReadingDayCompleteness")

        if not isinstance(gas_excluded, bool):
            raise RequestException("Invalid gasExcluded")

        if not isinstance(typename, str):
            raise RequestException("Invalid __typename")

        expected_costs_per_day = (
            MonthSummary.calculate_expected_costs_per_day(
                float(expected_costs),
                last_reading,
            )
            if expected_costs is not None
            else None
        )

        costs_per_day_till_now = MonthSummary.calculate_costs_per_day_till_now(
            float(actual_costs),
            last_reading,
        )

        return MonthSummary(
            _id=summary_id,
            actualCostsUntilLastMeterReadingDate=float(actual_costs),
            expectedCostsUntilLastMeterReadingDate=float(
                expected_costs_until,
            ),
            lastMeterReadingDate=last_reading,
            costs_per_day_till_now=costs_per_day_till_now,
            meterReadingDayCompleteness=completeness,
            gasExcluded=gas_excluded,
            typename=typename,
            expectedCosts=(float(expected_costs) if expected_costs is not None else None),
            expectedCostsPerDay=expected_costs_per_day,
        )

    @staticmethod
    def calculate_expected_costs_per_day(expected_costs: float, lastMeterReadingDate: str) -> float | None:
        """Calculate the expected costs per day."""
        last_meter_reading_date = datetime.strptime(lastMeterReadingDate, "%Y-%m-%d").replace(tzinfo=UTC)
        days_in_month = calendar.monthrange(last_meter_reading_date.year, last_meter_reading_date.month)[1]
        return expected_costs / days_in_month

    @staticmethod
    def calculate_costs_per_day_till_now(costs_till_now: float, lastMeterReadingDate: str) -> float:
        """Calculate the costs per day this month till now."""
        last_meter_reading_date = datetime.strptime(lastMeterReadingDate, "%Y-%m-%d").replace(tzinfo=UTC)
        days_elapsed = last_meter_reading_date.day - 1  # reading covers completed days
        if days_elapsed > 0:
            return costs_till_now / days_elapsed
        return costs_till_now  # day 1: no completed days yet

    @property
    def differenceUntilLastMeterReadingDate(self) -> float:
        """The difference between the expected costs and the actual costs."""
        return self.actualCostsUntilLastMeterReadingDate - self.expectedCostsUntilLastMeterReadingDate

    @property
    def differenceUntilLastMeterReadingDateAvg(self) -> float:
        last_meter_reading_date = datetime.strptime(self.lastMeterReadingDate, "%Y-%m-%d").replace(tzinfo=UTC)
        days_elapsed = last_meter_reading_date.day - 1
        if days_elapsed > 0:
            return self.differenceUntilLastMeterReadingDate / days_elapsed
        return self.differenceUntilLastMeterReadingDate


@dataclass
class ChargeSettings(DictLikeMixin):
    """Represents the charge settings for an enode charger."""

    calculated_deadline: datetime
    capacity: float
    deadline: datetime | None
    hour_friday: int
    hour_monday: int
    hour_saturday: int
    hour_sunday: int
    hour_thursday: int
    hour_tuesday: int
    hour_wednesday: int
    id: str
    is_smart_charging_enabled: bool
    is_solar_charging_enabled: bool
    max_charge_limit: int
    min_charge_limit: int
    initial_charge: float = 0.0  # EnodeChargers
    initial_charge_timestamp: datetime | None = None  # EnodeChargers

    @classmethod
    def from_dict(cls, data: dict) -> ChargeSettings:
        return cls(
            calculated_deadline=_parse_datetime(data["calculatedDeadline"]),
            capacity=data.get("capacity", 0.0),
            deadline=_parse_datetime(data.get("deadline")),
            hour_friday=data["hourFriday"],
            hour_monday=data["hourMonday"],
            hour_saturday=data["hourSaturday"],
            hour_sunday=data["hourSunday"],
            hour_thursday=data["hourThursday"],
            hour_tuesday=data["hourTuesday"],
            hour_wednesday=data["hourWednesday"],
            id=data["id"],
            initial_charge=data.get("initialCharge", 0.0),
            initial_charge_timestamp=_parse_datetime(data.get("initialChargeTimestamp")),
            is_smart_charging_enabled=data["isSmartChargingEnabled"],
            is_solar_charging_enabled=data.get("isSolarChargingEnabled", False),
            max_charge_limit=data["maxChargeLimit"],
            min_charge_limit=data["minChargeLimit"],
        )


@dataclass
class ChargeState(DictLikeMixin):
    """Represents the charge state for an enode charger.

    Several fields (battery_capacity, battery_level, charge_limit, range) are
    nullable because the Frank Energie API returns None for these when no
    vehicle is attached to the charger.
    """

    battery_capacity: float | None
    battery_level: int | None
    charge_limit: int | None
    charge_rate: float | None
    charge_time_remaining: int | None
    is_charging: bool
    is_fully_charged: bool | None
    is_plugged_in: bool
    last_updated: datetime | None
    power_delivery_state: str
    range: int | None

    @classmethod
    def from_dict(cls, data: dict) -> ChargeState:
        """
        Create a ChargeState instance from a dictionary.

        Args:
            data: Dictionary containing charge state information.

        Returns:
            ChargeState: Parsed ChargeState instance.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        if not isinstance(data, dict):
            raise ValueError("Expected data to be a dictionary.")

        # Convert timestamp to timezone-aware datetime
        last_updated_raw = data.get("lastUpdated")
        last_updated = _parse_iso_datetime(last_updated_raw, "lastUpdated")

        raw_battery_capacity = data.get("batteryCapacity")
        raw_battery_level = data.get("batteryLevel")
        raw_charge_limit = data.get("chargeLimit")
        raw_range = data.get("range")
        raw_is_fully_charged = data.get("isFullyCharged")

        return cls(
            battery_capacity=float(raw_battery_capacity) if raw_battery_capacity is not None else None,
            battery_level=int(raw_battery_level) if raw_battery_level is not None else None,
            charge_limit=int(raw_charge_limit) if raw_charge_limit is not None else None,
            charge_rate=float(data["chargeRate"]) if data.get("chargeRate") is not None else None,
            charge_time_remaining=(
                int(data["chargeTimeRemaining"]) if data.get("chargeTimeRemaining") is not None else None
            ),
            is_charging=bool(data["isCharging"]),
            is_fully_charged=bool(raw_is_fully_charged) if raw_is_fully_charged is not None else None,
            is_plugged_in=bool(data["isPluggedIn"]),
            last_updated=last_updated,
            power_delivery_state=str(data["powerDeliveryState"]),
            range=int(raw_range) if raw_range is not None else None,
        )


@dataclass
class VehicleInformation(DictLikeMixin):
    brand: str
    model: str
    vin: str
    year: int

    @classmethod
    def from_dict(cls, data: dict) -> VehicleInformation:
        return cls(
            brand=data["brand"],
            model=data["model"],
            vin=data["vin"],
            year=data["year"],
        )


@dataclass
class VehicleIntervention(DictLikeMixin):
    title: str
    description: str

    @classmethod
    def from_dict(cls, data: dict) -> VehicleIntervention:
        return cls(
            title=data["title"],
            description=data["description"],
        )


@dataclass
class Intervention:
    """Represents an intervention for an enode charger."""

    description: str
    title: str

    @classmethod
    def from_dict(cls, data: dict) -> Intervention:
        return cls(
            title=data["title"],
            description=data["description"],
        )


@dataclass
class EnodeVehicle(DictLikeMixin):
    """Represents a single enode vehicle."""

    id: str
    can_smart_charge: bool
    charge_settings: ChargeSettings
    charge_state: ChargeState
    information: VehicleInformation
    interventions: list[VehicleIntervention]
    is_reachable: bool
    last_seen: datetime | None

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> EnodeVehicle:
        return cls(
            id=data["id"],
            can_smart_charge=data["canSmartCharge"],
            charge_settings=ChargeSettings.from_dict(data["chargeSettings"]),
            charge_state=ChargeState.from_dict(data["chargeState"]),
            information=VehicleInformation.from_dict(data["information"]),
            interventions=[VehicleIntervention.from_dict(i) for i in data.get("interventions", [])],
            is_reachable=data["isReachable"],
            last_seen=_parse_datetime(data.get("lastSeen")),
        )


@dataclass
class EnodeVehicles:
    """Represents a collection of enode vehicles."""

    """This class holds a list of EnodeVehicle instances."""
    vehicles: list[EnodeVehicle]

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> EnodeVehicles:
        vehicle_dicts = data.get("data", {}).get("enodeVehicles", [])
        vehicles = [EnodeVehicle.from_dict(v) for v in vehicle_dicts]
        return cls(vehicles=vehicles)


@dataclass
class EnodeCharger:
    """Represents a single enode charger with relevant information."""

    can_smart_charge: bool
    charge_settings: ChargeSettings
    charge_state: ChargeState
    id: str
    information: dict
    interventions: list[Intervention]
    is_reachable: bool
    last_seen: datetime | None

    @classmethod
    def from_dict(cls, data: dict) -> EnodeCharger:
        """Create an instance of EnodeCharger from a dictionary."""
        charge_settings_data = data["chargeSettings"]
        charge_state_data = data["chargeState"]
        interventions_data = data["interventions"]

        charge_settings = ChargeSettings.from_dict(charge_settings_data)

        charge_state = ChargeState.from_dict(charge_state_data)

        interventions = [
            Intervention(description=intervention["description"], title=intervention["title"])
            for intervention in interventions_data
        ]

        return cls(
            can_smart_charge=data["canSmartCharge"],
            charge_settings=charge_settings,
            charge_state=charge_state,
            id=data["id"],
            information=data["information"],
            interventions=interventions,
            is_reachable=data["isReachable"],
            last_seen=_parse_iso_datetime(data.get("lastSeen")),
        )


@dataclass
class EnodeChargers:
    """Represents a collection of enode chargers."""

    chargers: list[EnodeCharger]

    @classmethod
    def from_dict(cls, data: list[dict]) -> EnodeChargers:
        """Create an instance of EnodeChargers from a list of dictionaries."""
        chargers = [EnodeCharger.from_dict(item) for item in data]
        return cls(chargers=chargers)

    def old_as_dict(self) -> dict[str, EnodeCharger]:
        """Convert the charger list to a dictionary keyed by charger ID."""
        return {charger.id: charger for charger in self.chargers}

    def as_dict(self) -> dict[str, EnodeCharger]:
        """Return only chargers with smart charging enabled as a dict keyed by charger ID."""
        return {charger.id: charger for charger in self.chargers if charger.charge_settings.is_smart_charging_enabled}


@dataclass
class Price:
    """Price data for a single price interval (e.g. PT15M)."""

    date_from: datetime
    date_till: datetime
    price_data: list[Price]
    energy_type: str | None = None
    market_price: float = 0.0
    market_price_tax: float = 0.0
    sourcing_markup_price: float = 0.0
    energy_tax_price: float = 0.0
    unit: str | None = None
    per_unit: str | None = None
    tax_rate: float = 0.0
    tax: float = 0.0
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    market_price_including_tax: float = 0.0
    market_price_including_tax_and_markup: float = 0.0

    def __post_init__(self) -> None:
        """Ensure that date_from is timezone-aware and normalized to UTC."""
        if self.date_from.tzinfo is None or self.date_from.tzinfo.utcoffset(self.date_from) is None:
            raise ValueError("date_from must be timezone-aware (include tzinfo).")

        # Log warning if not UTC, but convert safely
        if self.date_from.tzinfo != UTC:
            _LOGGER.debug("Normalizing date_from from %s to UTC.", self.date_from.tzinfo)
            self.date_from = self.date_from.astimezone(UTC)

        """Initialize energy_type if provided in data.
        This method sets the energy tax price based on the energy type.
        This tax is for The Netherlands and may change yearly.
        The values are based on the energy tax for electricity and gas in 2025.
        €0,10154×1,21=€0,12286 per kWh (<10.000 kWh)
        Iedere aansluiting krijgt in 2025 een vermindering van € 635,19 (inclusief btw) (tot ~4.700 kWh) via de belastingvermindering/regeling basisbehoefte

        Onderdeel	Tarief 2025
        Energiebelasting stroom (<10.000 kWh)	€ 0,10154/kWh excl. btw → € 0,12286/kWh incl. btw
        Energiebelasting stroom (>10.000 kWh)	€ 0,06937/kWh excl. btw → € 0,08400/kWh incl. btw
        Vermindering energiebelasting	€ 635,19 per jaar (incl. btw)
        """
        # if self.energy_type:
        #     if self.energy_type == "electricity":
        # self.energy_tax_price = 0.15239 # electricity tax 2023
        # self.energy_tax_price = 0.13165  # electricity tax 2024
        #         self.energy_tax_price = 0.1228634  # electricity tax 2025 incl. BTW
        #     if self.energy_type == "gas":
        # self.energy_tax_price = 0.5927 # gas tax 2023
        # self.energy_tax_price = 0.70544  # gas tax 2024
        #         self.energy_tax_price = 0.6995736  # gas tax 2025
        # not in use anymore, get energy_tax_price from API response

    def __init__(self, data: dict, energy_type: str | None = None) -> None:
        """Parse the response from the prices query."""
        self.energy_type = energy_type
        # self.energy_type = data.get("energy_type", None)

        date_from_str = data.get("from", "")
        date_till_str = data.get("till", "")
        self.date_from = None
        self.date_till = None

        if date_from_str:
            try:
                self.date_from = datetime.fromisoformat(date_from_str.replace("Z", _UTC_SUFFIX))
            except ValueError:
                logging.warning("Invalid ISO date format: '%s'", date_from_str)

        if date_till_str:
            try:
                self.date_till = datetime.fromisoformat(date_till_str.replace("Z", _UTC_SUFFIX))
            except ValueError:
                logging.warning("Invalid ISO date format: '%s'", date_till_str)

        """ The market price of the product or service. """
        self.market_price = data["marketPrice"]
        """ The amount of tax added to the market price. """
        self.market_price_tax = data["marketPriceTax"]
        """ The amount of sourcing markup added to the market price. """
        self.sourcing_markup_price = data["sourcingMarkupPrice"]
        self.energy_tax_price = data["energyTaxPrice"]
        self.market_price_including_tax = self.market_price + self.market_price_tax

        # Tax added to the market price including tax and markup
        self.market_price_including_tax_and_markup = (
            self.market_price + self.market_price_tax + self.sourcing_markup_price
        )

        self.per_unit = data.get("perUnit")

    def __str__(self) -> str:
        """Return a string representation of this price entry."""
        date_from_str = self.date_from.isoformat() if self.date_from else "N/A"
        date_till_str = self.date_till.isoformat() if self.date_till else "N/A"
        return f"{date_from_str} -> {date_till_str}: {self.total:.4f} {self.per_unit or ''}"

    @property
    def ET(self, data) -> str:  # not in use anymore
        """Returns energy type 'electricity' or 'gas'."""
        if "energy_type" in data:
            self.energy_type = data["energy_type"]
            if self.energy_type == "electricity":
                # self.energy_tax_price = 0.15239 # electricity tax 2023
                # self.energy_tax_price = 0.13165  # electricity tax 2024
                self.energy_tax_price = 0.1228634  # electricity tax 2025
            if self.energy_type == "gas":
                # self.energy_tax_price = 0.5927 # gas tax 2023
                # self.energy_tax_price = 0.70544  # gas tax 2024
                self.energy_tax_price = 0.6995736  # gas tax 2025
            return data["energy_type"]
        else:
            return None

    @property
    def for_current_quarter_hour(self) -> bool:
        """True when the current UTC time falls within this 15-minute interval.

        Is this interval active now?

        Identical logic to ``for_now``; exists as a named alias so sensor code
        can express intent clearly when working with PT15M data.
        """
        now = datetime.now(UTC)
        return self.date_from <= now < self.date_till

    @property
    def for_now(self) -> bool:
        """Return True when the current UTC time falls within this price interval."""
        now = datetime.now(UTC)
        return self.date_from <= now < self.date_till

    @property
    def for_current_hour(self) -> bool:
        """Return True if current time falls within [date_from, date_till)."""
        now = datetime.now(UTC)

        start = getattr(self, "date_from", None)
        end = getattr(self, "date_till", None)

        if not isinstance(start, datetime) or not isinstance(end, datetime):
            _LOGGER.debug(
                "Invalid datetime range: start=%s, end=%s",
                start,
                end,
            )
            return False

        if start.tzinfo is None or end.tzinfo is None:
            _LOGGER.debug(
                "Naive datetime detected: start=%s, end=%s",
                start,
                end,
            )
            return False

        start_utc = start.astimezone(UTC)
        end_utc = end.astimezone(UTC)

        if start_utc >= end_utc:
            _LOGGER.debug(
                "Invalid interval (start >= end): start=%s, end=%s",
                start_utc,
                end_utc,
            )
            return False

        return start_utc <= now < end_utc

    @property
    def for_future_hour(self) -> bool:
        """Whether this price entry is for and hour after the current one."""
        return self.date_from.hour > datetime.now(UTC).hour

    @property
    def for_future(self) -> bool:
        """Return True if this price interval starts after the current UTC time."""
        return self.date_from > datetime.now(UTC)

    @property
    def for_today(self) -> bool:
        """Return whether this price entry starts during the current local day (DST-safe).

        This ensures correct detection of the last hour (23:00–00:00),
        even when the interval ends on the next day or during DST changes.
        """
        # Huidige lokale kalenderdag
        today_local = datetime.now(UTC).astimezone(LOCAL_TZ).date()

        # Datum waarop deze prijs start
        date_from_local = self.date_from.astimezone(LOCAL_TZ).date()

        return date_from_local == today_local

    @property
    def for_tomorrow(self) -> bool:
        """Return whether this price entry is for tomorrow (DST-safe)."""

        # Huidige lokale datum (met juiste DST status)
        today_local = datetime.now(UTC).astimezone(LOCAL_TZ).date()
        tomorrow_local = today_local + timedelta(days=1)

        # Datum van deze prijs in lokale tijd
        date_local = self.date_from.astimezone(LOCAL_TZ).date()

        return date_local == tomorrow_local

    @property
    def for_upcoming(self) -> bool:
        """Whether this price entry is for a hour after the current one."""
        now = datetime.now(UTC).astimezone()
        return self.date_from > now

    @property
    def for_previous_hour(self) -> bool:
        """Whether this price entry is for the previous hour."""
        now = datetime.now(UTC).astimezone()  # Convert to local timezone
        previous_hour_start = now.replace(microsecond=0, second=0, minute=0) - timedelta(hours=1)
        return self.date_from == previous_hour_start

    @property
    def for_next_hour(self) -> bool:
        """Whether this price entry is for the next hour."""
        now = datetime.now(UTC).astimezone()  # Convert to local timezone
        next_hour_start = now.replace(microsecond=0, second=0, minute=0) + timedelta(hours=1)
        next_hour_end = next_hour_start + timedelta(hours=1)
        return next_hour_start <= self.date_from < next_hour_end

    @property
    def previous_hour(self):
        """Price that was the previous hour applicable."""
        return next((hour for hour in self.price_data if hour.for_previous_hour), None)

    @property
    def next_hour(self):
        """Price that is-the next hour applicable."""
        return next((hour for hour in self.price_data if hour.for_next_hour), None)

    # Calculate the market price with tax by adding marketPrice and marketPriceTax
    @property
    def market_price_with_tax(self) -> float:
        """The market price including tax."""
        return self.market_price + self.market_price_tax

    # Calculate the market price with tax and sourcing markup by adding marketPrice, marketPriceTax and sourcing_markup_price
    @property
    def market_price_with_tax_and_markup(self) -> float:
        """The market price including tax."""
        return self.market_price + self.market_price_tax + self.sourcing_markup_price

    @property
    def total(self) -> float:
        """The total price for this hour."""
        if not hasattr(self, "_total"):
            self._total = self.market_price + self.market_price_tax + self.sourcing_markup_price + self.energy_tax_price
        return self._total

    @staticmethod
    def average_price_for_current_hour(prices: list[object]) -> float | None:
        """Return the average price for the current hour across a list of prices."""
        current = [p for p in prices if getattr(p, "for_now", False)]

        if not current:
            return None

        return sum(p.total for p in current) / len(current)

    def calculate_stats1(self, prices: list[Price]) -> dict[str, float]:
        if not prices:
            return {}

        price_values = [price.market_price for price in prices]
        total_prices = [price.total for price in prices]
        return {
            "min": min(price_values),
            "max": max(price_values),
            "avg": mean(total_prices),
        }

    @staticmethod
    def calculate_stats2(prices: list[float]) -> dict[str, float]:
        if not prices:
            return {}

        # Calculate the minimum price
        min_price = min(prices)

        # Calculate the maximum price
        max_price = max(prices)

        # Calculate the average price
        avg_price = mean(prices)

        # Calculate the total price
        total_price = sum(prices)

        # Calculate the standard deviation
        n = len(prices)
        std_dev = (sum((x - avg_price) ** 2 for x in prices) / n) ** 0.5

        # Create a dictionary to store the calculated statistics
        stats = {
            "min_price": min_price,
            "max_price": max_price,
            "avg_price": avg_price,
            "total_price": total_price,
            "std_dev": std_dev,
        }

        return stats

    @staticmethod
    def calculate_stats3(data: dict) -> dict[str, dict[str, float]]:
        if not data:
            return {}
        electricity_prices = [entry["marketPrice"] for entry in data["marketPricesElectricity"]]
        gas_prices = [entry["marketPrice"] for entry in data["marketPricesGas"]]

        electricity_mean = mean(electricity_prices)
        gas_mean = mean(gas_prices)

        electricity_min = min(electricity_prices)
        gas_min = min(gas_prices)

        electricity_max = max(electricity_prices)
        gas_max = max(gas_prices)

        electricity_std_dev = (
            sum((x - electricity_mean) ** 2 for x in electricity_prices) / len(electricity_prices)
        ) ** 0.5
        gas_std_dev = (sum((x - gas_mean) ** 2 for x in gas_prices) / len(gas_prices)) ** 0.5

        return {
            "electricity": {
                "mean": electricity_mean,
                "min": electricity_min,
                "max": electricity_max,
                "std_dev": electricity_std_dev,
            },
            "gas": {"mean": gas_mean, "min": gas_min, "max": gas_max, "std_dev": gas_std_dev},
        }


@dataclass
class PriceDataAvg:
    """Dataclass representing average price data for a time period."""

    values: list[Price]
    total: float
    market_price_with_tax_and_markup: float
    market_markup_price: float
    market_price_with_tax: float
    market_price_tax: float
    market_price: float

    @property
    def per_unit(self) -> str | None:
        """Return the perUnit value of the prices."""
        for price in self.values:
            if getattr(price, "per_unit", None):
                return price.per_unit
        return None


@dataclass
class PriceData:
    """Price data for a period of time.

    Pass a raw list of price dicts and an energy type; the dataclass
    builds the typed ``Price`` objects in ``__post_init__``.

    Example::

        pd = PriceData(prices=raw_list, energy_type="electricity")
    """

    # ------------------------------------------------------------------ #
    # Fields — the only names @dataclass is allowed to manage             #
    # ------------------------------------------------------------------ #
    prices: list[dict] = field(default_factory=list)
    """Raw price dicts received from the API (input only)."""

    energy_type: str | None = None
    gas_unit: str | None = None
    elec_unit: str | None = None
    gas_resolution: str | None = None
    elec_resolution: str | None = None
    resolution_minutes: int = 60

    # ------------------------------------------------------------------ #
    # Post-init — build typed Price objects from the raw dicts            #
    # ------------------------------------------------------------------ #
    def __post_init__(self) -> None:
        """Convert raw API dicts to typed Price objects."""
        self.price_data: list[Price] = [Price({**p, "energy_type": self.energy_type}) for p in self.prices]

    # ------------------------------------------------------------------ #
    # Dunder helpers                                                       #
    # ------------------------------------------------------------------ #
    def __add__(self, other: PriceData) -> PriceData:
        """Merge two PriceData objects (preserves energy_type of self)."""
        merged = PriceData(energy_type=self.energy_type)
        merged.price_data = self.price_data + other.price_data
        return merged

    def __str__(self) -> str:
        """Return a string representation of this price data."""
        return str([str(price) for price in self.price_data])

    def filter_prices(self, start_date: datetime, end_date: datetime) -> list[Price]:
        """Filter prices based on start and end dates."""
        return [price for price in self.price_data if start_date <= price.date_from <= end_date]

    # ------------------------------------------------------------------ #
    # Properties — computed from self.price_data, never stored as fields  #
    # ------------------------------------------------------------------ #
    @property
    def per_unit(self) -> str | None:
        """Return the perUnit value of the prices."""
        for price in self.price_data:
            if getattr(price, "per_unit", None):
                return price.per_unit
        return None

    @property
    def all(self) -> list[Price]:
        """All price entries."""
        return self.price_data

    @property
    def today(self) -> list[Price]:
        """Prices for today."""
        return [hour for hour in self.price_data if hour.for_today]

    @property
    def tomorrow(self) -> list[Price]:
        """Prices for tomorrow."""
        return [hour for hour in self.price_data if hour.for_tomorrow]

    @property
    def previous_hour(self) -> Price | None:
        """Price that was the previous hour applicable."""
        return next((hour for hour in self.price_data if hour.for_previous_hour), None)

    @property
    def current(self) -> Price | None:
        """Return the price entry that is currently active (interval-based).

        Works with any resolution (PT15M, PT30M, PT60M) by checking whether
        the current time is within [date_from, date_till) in local time.
        """
        now_local = datetime.now(UTC).astimezone(LOCAL_TZ)

        for price in self.price_data:
            start = price.date_from.astimezone(LOCAL_TZ)
            end = price.date_till.astimezone(LOCAL_TZ)

            if start <= now_local < end:
                return price

        return None

    @property
    def current_quarter_hour(self) -> Price | None:
        """Return the price entry that covers the current 15-minute interval.

        Works identically to ``current_hour`` but is meaningful only when the
        data was fetched at PT15M resolution.  Falls back gracefully to ``None``
        when price_data is empty or no interval matches (e.g. a gap in the API
        response).

        Returns:
            The matching ``Price`` object, or ``None`` if not found.
        """
        now = datetime.now(UTC)
        return next(
            (p for p in self.price_data if p.date_from <= now < p.date_till),
            None,
        )

    @property
    def prices_for_current_hour(self) -> list[Price]:
        """Which intervals belong to this hour?"""
        return [price for price in self.price_data if price.for_current_hour]

    @property
    def average_current_hour(self) -> Price:
        """Average price for the current hour."""
        current_hour_prices = self.prices_for_current_hour
        if not current_hour_prices:
            return None
        average_price = mean(price.total for price in current_hour_prices)
        return average_price

    @property
    def current_hour(self) -> Price | None:
        """Price that's currently applicable."""
        matching_hours = [hour for hour in self.price_data if hour.for_now]
        if matching_hours:
            return matching_hours[0]
        else:  # only occurs when hour.for_now is not in range of price_data
            return None

    @property
    def next_hour(self) -> Price | None:
        """Price that's next hour applicable."""
        return next((hour for hour in self.price_data if hour.for_next_hour), None)

    @property
    def today_tax_markup_avg(self) -> float:
        """Average market price including tax and markup for today."""
        today_market_tax_markup = [hour.market_price_with_tax_and_markup for hour in self.today_prices]
        return mean(today_market_tax_markup)

    @property
    def today_min(self) -> Price | None:
        """Price with the lowest total for today."""
        return min(self.today, key=lambda hour: hour.total, default=None)

    @property
    def today_max(self) -> Price | None:
        """Price with the highest total for today."""
        return max(self.today, key=lambda hour: hour.total, default=None)

    @property
    def today_avg(self) -> float | None:
        """Average price for today."""
        return mean(hour.total for hour in self.today) if self.today else None

    @property
    def tomorrow_average_price(self) -> float | None:
        """Average total price for tomorrow."""
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)

        if not tomorrow_prices:
            return None

        average_price = mean(price.total for price in tomorrow_prices)
        rounded_average_price = round(average_price, DEFAULT_ROUND)

        return rounded_average_price

    @property
    def tomorrow_average_price_including_tax(self) -> float | None:
        """Average total price including tax and markup for tomorrow."""
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)

        if not tomorrow_prices:
            return None

        average_price = mean(price.market_price_including_tax for price in tomorrow_prices)
        rounded_average_price = round(average_price, DEFAULT_ROUND)

        return rounded_average_price

    @property
    def tomorrow_average_price_including_tax_and_markup(self) -> float | None:
        """Average total price including tax and markup for tomorrow."""
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)

        if not tomorrow_prices:
            return None

        average_price = mean(price.market_price_including_tax_and_markup for price in tomorrow_prices)
        rounded_average_price = round(average_price, DEFAULT_ROUND)

        return rounded_average_price

    @property
    def tomorrow_average_market_price(self) -> float | None:
        """Average market price for tomorrow."""
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)

        if not tomorrow_prices:
            return None

        average_price = mean(price.market_price for price in tomorrow_prices)
        rounded_average_price = round(average_price, DEFAULT_ROUND)

        return rounded_average_price

    @property
    def tomorrow_min(self) -> Price | None:
        """Price with the lowest total for today."""
        return min(self.tomorrow, key=lambda hour: hour.total, default=None)

    @property
    def tomorrow_max(self) -> Price | None:
        """Price with the highest total for today."""
        return max(self.tomorrow, key=lambda hour: hour.total, default=None)

    @property
    def all_min(self) -> Price | None:
        """Price with the lowest total for all hours."""
        return min(self.price_data, key=lambda hour: hour.total, default=None)

    @property
    def all_max(self) -> Price | None:
        """Price with the highest total for all hours."""
        return max(self.price_data, key=lambda hour: hour.total, default=None)

    @property
    def upcoming(self) -> list[Price]:
        """Prices for upcoming hours."""
        return [hour for hour in self.price_data if hour.for_upcoming]

    @property
    def all_attr(self):
        """Electricity price data for the all hours"""
        all_data = []
        total_price = 0
        for hour in self.price_data:
            all_data.append(
                {"from": hour.date_from.isoformat(), "till": hour.date_till.isoformat(), "price": hour.total}
            )
            total_price += hour.total
        return {"all_hours": all_data, "average": total_price / len(all_data) if len(all_data) > 0 else 0}

    @property
    def upcoming_attr(self):
        """Electricity price data for the upcoming hours"""
        upcoming_data = []
        total_price = 0
        for hour in self.price_data:
            if hour.for_upcoming:
                upcoming_data.append(
                    {"from": hour.date_from.isoformat(), "till": hour.date_till.isoformat(), "price": hour.total}
                )
                total_price += hour.total
        return {"upcoming": upcoming_data, "average": total_price / len(upcoming_data) if len(upcoming_data) > 0 else 0}

    @property
    def upcoming_min(self) -> Price | None:
        """Return the upcoming price entry with the lowest total."""
        return min(list(self.upcoming), key=lambda hour: hour.total, default=None)

    @property
    def upcoming_max(self) -> Price | None:
        """Return the upcoming price entry with the highest total."""
        return max(list(self.upcoming), key=lambda hour: hour.total, default=None)

    @staticmethod
    def avg(prices: Iterable[float]) -> float | None:
        """Calculate the average price of a list of prices."""
        prices_list = list(prices)

        if not prices_list:
            return None

        return mean(prices_list)

    @staticmethod
    def safe_avg(values: Iterable[float | int]) -> float | None:
        """Return average of numeric values or None if empty."""
        values_list = [float(v) for v in values if v is not None]

        if not values_list:
            return None

        return mean(values_list)

    @property
    def today_tax_avg(self) -> float:
        """Average market price including tax and markup for today."""
        today_market_prices_tax_markup = [hour.market_price_with_tax for hour in self.today_prices]
        return mean(today_market_prices_tax_markup)

    def average_price(self, start_date: datetime, end_date: datetime) -> float:
        """Get the average price for a period of time."""
        prices = self.filter_prices(start_date, end_date)
        if prices:
            return mean(price.total for price in prices)
        return 0.0

    @property
    def upcoming_prices(self) -> list[Price]:
        """Return prices for hours after the current one."""
        if not self.price_data:
            return []

        return [hour for hour in self.price_data if getattr(hour, "for_upcoming", False)]

    @property
    def today_prices(self) -> list[Price]:
        """Return prices for today."""
        if not self.price_data:
            return []

        return [hour for hour in self.price_data if getattr(hour, "for_today", False)]

    @property
    def tomorrow_prices(self) -> list[Price]:
        """Return prices for tomorrow."""
        if not self.price_data:
            return []

        return [hour for hour in self.price_data if getattr(hour, "for_tomorrow", False)]

    def asdict(
        self,
        attr: str,
        upcoming_only: bool = False,
        today_only: bool = False,
        tomorrow_only: bool = False,
        timezone: str | None = None,
    ) -> list[dict]:
        """
        Return a list of dictionaries suitable for use as entity attribute data.

        Args:
            attr (str): The attribute name (e.g., 'marketPrice') to extract from each price object.
            upcoming_only (bool): If True, include only upcoming prices.
            today_only (bool): If True, include only today's prices.
            tomorrow_only (bool): If True, include only tomorrow's prices.
            timezone (str | None): The timezone to localize the 'from' and 'till' datetimes. Defaults to UTC.

        Returns:
            list[dict]: A list of dicts with keys 'from', 'till', and the selected 'price'.
        """
        try:
            tz = ZoneInfo(timezone) if timezone else ZoneInfo("UTC")

            # self.price_data is altijd een list
            #           if isinstance(self.price_data, list):
            if upcoming_only:
                prices = self.upcoming_prices
            elif today_only:
                prices = self.today_prices
            elif tomorrow_only:
                prices = self.tomorrow_prices
                if not prices:
                    return [{"message": "No prices for tomorrow."}]
            else:
                prices = self.price_data
            #            else:
            #                if upcoming_only:
            #                    prices = [self]
            #                elif today_only:
            #                    prices = [p for p in self.price_data if p.for_today]
            #                elif tomorrow_only:
            #                    prices = [p for p in self.price_data if p.for_tomorrow]
            #                    if not prices:
            #                        return [{'message': 'No prices for tomorrow.'}]
            #                else:
            #                    prices = [self.price_data]

            # Map prices to dictionaries
            return [
                {
                    "from": price.date_from.astimezone(tz),
                    "till": price.date_till.astimezone(tz),
                    "price": round(getattr(price, attr), 3),
                }
                for price in prices
            ]

        except AttributeError as err:
            _LOGGER.error("Price object has no attribute '%s'", err)
            return [{"error": f"Price object has no attribute: {err}"}]

        except Exception as exc:
            _LOGGER.exception(
                "Failed to convert price data to dict (attr=%s, upcoming_only=%s, today_only=%s, tomorrow_only=%s, tz_name=%s): %s",
                attr,
                upcoming_only,
                today_only,
                tomorrow_only,
                timezone,
                exc,
            )
            return [{"error": f"Failed to convert price data: {exc}"}]

    @staticmethod
    def asdict_to_local(prices_dict, timezone):
        """Convert prices dictionary to local timezone."""
        local_prices = []
        for price_data in prices_dict:
            local_date_from = price_data["from"].astimezone(timezone)
            local_date_till = price_data["till"].astimezone(timezone)
            local_price_data = {"from": local_date_from, "till": local_date_till, "price": price_data["price"]}
            local_prices.append(local_price_data)
        return local_prices

    def test_asdict(self, attr):  # remove me
        """Return a dict that can be used as entity attribute data."""
        result = []
        for e in self.price_data:
            data = {
                "from": e.date_from,
                "till": e.date_till,
                "date_from": e.date_from,
                "date_till": e.date_till,
                "market_price": e.market_price,
                "market_price_tax": e.market_price_tax,
                "sourcing_markup_price": e.sourcing_markup_price,
                "energy_tax_price": e.energy_tax_price,
                "total": e.total,
                "price": getattr(e, attr),
            }
            result.append(data)
        return result

    def calculate_stats(self) -> dict:
        """Calculate summary statistics for electricity and gas prices."""
        electricity_prices = [price.total for price in self if price.electricity]
        gas_prices = [price.total for price in self if price.gas]

        electricity_mean = mean(electricity_prices)
        gas_mean = mean(gas_prices)

        electricity_min = min(electricity_prices)
        gas_min = min(gas_prices)

        electricity_max = max(electricity_prices)
        gas_max = max(gas_prices)

        return {
            "electricity": {"mean": electricity_mean, "min": electricity_min, "max": electricity_max},
            "gas": {"mean": gas_mean, "min": gas_min, "max": gas_max},
        }

    @property
    def today_market_avg(self) -> float:
        """Average market price for today."""
        today_market_prices = [hour.market_price for hour in self.today_prices]
        return mean(today_market_prices)

    def get_price_statistics(price_data: PriceData, start_date: datetime, end_date: datetime) -> dict | None:
        """Calculate statistics for prices within a specific date range."""
        filtered_prices = price_data.filter_prices(start_date, end_date)
        if filtered_prices:
            prices = [price.total for price in filtered_prices]
            return {
                "min_price": min(prices),
                "max_price": max(prices),
                "avg_price": mean(prices),
                "total_price": sum(prices),
                "std_dev": (sum((x - mean(prices)) ** 2 for x in prices) / len(prices)) ** 0.5,
            }
        return None

    @property
    def all_avg(self):
        """Get the average of all prices."""
        all_prices = list(self.price_data)

        if not all_prices:
            return None

        avg = round(mean(price.total for price in all_prices), DEFAULT_ROUND)
        market_price_with_tax_and_markup_avg = round(
            mean(price.market_price_with_tax_and_markup for price in all_prices), DEFAULT_ROUND
        )
        market_price_with_tax_avg = round(mean(price.market_price_with_tax for price in all_prices), DEFAULT_ROUND)
        market_price_tax_avg = round(mean(price.market_price_tax for price in all_prices), DEFAULT_ROUND)
        market_price_markup_avg = round(mean(price.sourcing_markup_price for price in all_prices), DEFAULT_ROUND)
        market_price_avg = round(mean(price.market_price for price in all_prices), DEFAULT_ROUND)

        return PriceDataAvg(
            values=all_prices,
            total=avg,
            market_price_with_tax_and_markup=market_price_with_tax_and_markup_avg,
            market_markup_price=market_price_markup_avg,
            market_price_with_tax=market_price_with_tax_avg,
            market_price_tax=market_price_tax_avg,
            market_price=market_price_avg,
        )

    @property
    def upcoming_avg(self) -> PriceDataAvg | None:
        """Get the average of upcoming prices."""
        upcoming_prices = self.get_prices_for_time_period(TimePeriod.UPCOMING)

        if not upcoming_prices:
            return None

        avg = round(mean(price.total for price in upcoming_prices), DEFAULT_ROUND)
        market_price_with_tax_and_markup_avg = round(
            mean(price.market_price_with_tax_and_markup for price in upcoming_prices), DEFAULT_ROUND
        )
        market_price_with_tax_avg = round(mean(price.market_price_with_tax for price in upcoming_prices), DEFAULT_ROUND)
        market_price_tax_avg = round(mean(price.market_price_tax for price in upcoming_prices), DEFAULT_ROUND)
        market_price_markup_avg = round(mean(price.sourcing_markup_price for price in upcoming_prices), DEFAULT_ROUND)
        market_price_avg = round(mean(price.market_price for price in upcoming_prices), DEFAULT_ROUND)

        """
        PriceDataAvg = namedtuple('PriceDataAvg', [
            'values', 'total', 'market_price_with_tax_and_markup',
            'market_markup_price', 'market_price_with_tax',
            'market_price_tax', 'market_price'
        ])
        """

        return PriceDataAvg(
            values=upcoming_prices,
            total=avg,
            market_price_with_tax_and_markup=market_price_with_tax_and_markup_avg,
            market_markup_price=market_price_markup_avg,
            market_price_with_tax=market_price_with_tax_avg,
            market_price_tax=market_price_tax_avg,
            market_price=market_price_avg,
        )

    @property
    def tomorrow_avg(self) -> PriceDataAvg | None:
        """Get the average of tomorrow's prices."""

        # tomorrow_prices = [
        #     price for price in self.price_data
        #     if tomorrow_start <= price.date_from < tomorrow_end
        # ]
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)

        if not tomorrow_prices:
            return None

        avg = round(mean(price.total for price in tomorrow_prices), DEFAULT_ROUND)
        market_price_with_tax_and_markup_avg = round(
            mean(price.market_price_including_tax_and_markup for price in tomorrow_prices), DEFAULT_ROUND
        )
        market_price_with_tax_avg = round(
            mean(price.market_price_including_tax for price in tomorrow_prices), DEFAULT_ROUND
        )
        market_price_tax_avg = round(mean(price.market_price_tax for price in tomorrow_prices), DEFAULT_ROUND)
        market_markup_price_avg = round(mean(price.sourcing_markup_price for price in tomorrow_prices), DEFAULT_ROUND)
        market_price_avg = round(mean(price.market_price for price in tomorrow_prices), DEFAULT_ROUND)

        """
        PriceDataAvg = namedtuple('PriceDataAvg', [
            'values', 'total', 'market_price_with_tax_and_markup',
            'market_markup_price', 'market_price_with_tax',
            'market_price_tax', 'market_price'
        ])
        """

        return PriceDataAvg(
            values=tomorrow_prices,
            total=avg,
            market_price_with_tax_and_markup=market_price_with_tax_and_markup_avg,
            market_markup_price=market_markup_price_avg,
            market_price_with_tax=market_price_with_tax_avg,
            market_price_tax=market_price_tax_avg,
            market_price=market_price_avg,
        )

    @property
    def tomorrow_prices_market(self) -> list:
        """Get the market prices for tomorrow"""
        current_hour_utc = datetime.now(UTC).hour
        if not self.price_data or current_hour_utc > 21 or current_hour_utc < FETCH_TOMORROW_HOUR_UTC:
            return None
        # if -1 < datetime.now(timezone.utc).hour < 15:
        #    return None

        today_prices = []
        tomorrow_prices = []
        for price in self.price_data:
            if price.for_today:
                today_prices.append(price.market_price)
            elif price.for_tomorrow:
                tomorrow_prices.append(price.market_price)
        if tomorrow_prices:
            return round(mean(tomorrow_prices), DEFAULT_ROUND)
        return None

    @property
    def tomorrow_prices_market_tax(self) -> list:
        """Get the market prices incl tax for tomorrow"""
        current_hour_utc = datetime.now(UTC).hour
        if not self.price_data or current_hour_utc > 21 or current_hour_utc < FETCH_TOMORROW_HOUR_UTC:
            return None

        #        if not self.price_data:
        #            return None
        #        if -1 < datetime.now(timezone.utc).hour < 15:
        #            return None

        today_prices = []
        tomorrow_prices = []
        for price in self.price_data:
            if price.for_today:
                today_prices.append(price.market_price_including_tax)
            elif price.for_tomorrow:
                tomorrow_prices.append(price.market_price_including_tax)
        if tomorrow_prices:
            return round(mean(tomorrow_prices), DEFAULT_ROUND)
        return None

    @property
    def tomorrow_prices_market_tax_markup(self) -> list:
        """Get the market prices incl tax and markup for tomorrow"""
        current_hour_utc = datetime.now(UTC).hour
        if not self.price_data or current_hour_utc > 21 or current_hour_utc < FETCH_TOMORROW_HOUR_UTC:
            return None

        #        if not self.price_data:
        #            return None
        #        if -1 < datetime.now(timezone.utc).hour < 15:
        #            return None

        today_prices = []
        tomorrow_prices = []
        for price in self.price_data:
            if price.for_today:
                today_prices.append(price.market_price_including_tax_and_markup)
            elif price.for_tomorrow:
                tomorrow_prices.append(price.market_price_including_tax_and_markup)
        if tomorrow_prices:
            return round(mean(tomorrow_prices), DEFAULT_ROUND)
        return None

    @property
    def today_prices_total(self) -> list:
        """Get the market prices for today"""
        if not self.price_data:
            return None

        today_prices = []
        for price in self.price_data:
            if price.for_today:
                today_prices.append(price.total)
        if today_prices:
            return round(mean(today_prices), DEFAULT_ROUND)
        return None

    @property
    def tomorrow_prices_total(self) -> list:
        """Get the market prices for tomorrow"""
        current_hour_utc = datetime.now(UTC).hour
        if not self.price_data or current_hour_utc > 21 or current_hour_utc < FETCH_TOMORROW_HOUR_UTC:
            return None

        #        if not self.price_data:
        #            return None
        #        if -1 < datetime.now(timezone.utc).hour < 15:
        #            return None

        tomorrow_prices = []
        for price in self.price_data:
            if price.for_tomorrow:
                tomorrow_prices.append(price.total)
        if tomorrow_prices:
            return round(mean(tomorrow_prices), DEFAULT_ROUND)
        return None

    @property
    def length(self) -> int:
        """Return the number of price entries."""
        if not self.price_data:
            return 0

        return len(self.price_data)

    @property
    def upcoming_market_avg(self) -> float | None:
        """Calculate the average market price of upcoming prices."""
        if self.current_hour is None:
            return None

        current_hour_end = getattr(self.current_hour, "date_till", None)
        if current_hour_end is None:
            return None

        if not self.price_data:
            return None

        total = 0.0
        count = 0

        for price in self.price_data:
            date_from = price.date_from
            if not date_from or date_from <= current_hour_end:
                continue

            value = price.market_price
            if value is None:
                continue

            try:
                total += float(value)
                count += 1
            except (TypeError, ValueError):
                continue

        if count == 0:
            return None

        return total / count

    @property
    def upcoming_market_tax_markup_avg(self):
        """Calculate the average market price with tax of upcoming prices."""
        if not self.current_hour or not self.price_data or not self.current_hour.date_till:
            return None
        current_hour = self.current_hour
        upcoming_prices = [price for price in self.price_data if price.date_from > current_hour.date_till]
        total_price = sum([price.market_price_with_tax_and_markup for price in upcoming_prices])
        if upcoming_prices:
            return total_price / len(upcoming_prices)
        else:
            return None

    @property
    def upcoming_market_tax_avg(self):
        """Calculate the average market price with tax of upcoming prices."""
        if not self.current_hour or not self.price_data or not self.current_hour.date_till:
            return None
        current_hour_end = self.current_hour.date_till
        upcoming_prices = [price for price in self.price_data if price.date_from > current_hour_end]

        if not upcoming_prices:
            return None

        total_price_with_tax = sum(price.market_price_with_tax for price in upcoming_prices)
        average_price_with_tax = total_price_with_tax / len(upcoming_prices)

        return average_price_with_tax

    @property
    def today_gas_before6am(self) -> list[Price]:
        """Get a list of gas prices for today before 6AM."""
        return [price.total for price in self.price_data if price.for_today and price.date_from.hour < 6]

    @property
    def today_gas_after6am(self) -> list[Price]:
        """Get a list of gas prices for today after 6AM."""
        return [price.total for price in self.price_data if price.for_today and price.date_from.hour >= 6]

    @property
    def tomorrow_gas_before6am(self) -> list[Price]:
        """Get a list of gas prices for tomorrow before 6AM."""
        return [price.total for price in self.price_data if price.for_tomorrow and price.date_from.hour < 6]

    @property
    def tomorrow_gas_after6am(self) -> list[Price]:
        """Get a list of gas prices for tomorrow after 6AM."""
        return [price.total for price in self.price_data if price.for_tomorrow and price.date_from.hour >= 6]

    def get_prices_for_time_period(self, period: TimePeriod):
        if period == TimePeriod.TODAY:
            return [hour for hour in self.price_data if hour.for_today]
        elif period == TimePeriod.TOMORROW:
            return [hour for hour in self.price_data if hour.for_tomorrow]
        elif period == TimePeriod.UPCOMING:
            return [hour for hour in self.price_data if hour.for_upcoming]
        else:
            raise ValueError(f"Invalid time period: {period}")


@dataclass
class MarketPrices:
    """Market prices for electricity and gas.

    Attributes:
    electricity (PriceData): The electricity price data.
    gas (PriceData): The gas price data.
    energy_type (Optional[str]): The type of energy (e.g., 'electricity' or 'gas').
    energy_country (str): The country code ('NL' or 'BE') for which the prices apply.
    today (list): Prices for today.
    tomorrow (list): Prices for tomorrow.
    """

    # note: zet velden zonder default altijd voor velden met default

    electricity: PriceData
    gas: PriceData
    energy_country: str
    energy_type: str | None = None
    today: list[object] = field(default_factory=list)
    tomorrow: list[object] = field(default_factory=list)

    #    def __init__(self, electricity: Optional[PriceData] = None, gas: Optional[PriceData] = None, energy_type: Optional[str] = None) -> None:
    #         self.electricity = electricity
    #         self.gas = gas
    #         self.energy_type = energy_type

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> MarketPrices:
        """Parse the response from the marketPrices query."""
        energy_country = "NL"
        _LOGGER.debug("Prices response keys: %s", list(data.keys()))

        # --- Errors ---
        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            message = first.get("message") if isinstance(first, dict) else None

            # API returns this as an "error", but it represents a valid empty dataset
            if isinstance(message, str) and "No marketprices found" in message:
                return cls(
                    electricity=PriceData([], energy_type="electricity"),
                    gas=PriceData([], energy_type="gas"),
                    energy_country=energy_country,
                )

            raise RequestException(str(message) if message else "Unknown error")

        # --- Root validation ---
        root = data.get("data")
        if not isinstance(root, dict):
            raise RequestException("Missing 'data' in NL response")

        # Get market prices from the root
        market_prices = root.get("marketPrices")
        if not isinstance(market_prices, dict):
            raise RequestException("Missing 'marketPrices' in response")

        _LOGGER.debug("Market Prices payload: %s", market_prices)

        # --- Electricity ---
        electricity_raw = market_prices.get("electricityPrices", [])
        if not isinstance(electricity_raw, list):
            _LOGGER.warning("electricityPrices is not a list: %s", type(electricity_raw))
            electricity_raw = []

        # --- Gas ---
        gas_raw = market_prices.get("gasPrices", [])
        if not isinstance(gas_raw, list):
            _LOGGER.warning("gasPrices is not a list: %s", type(gas_raw))
            gas_raw = []

        if len(electricity_raw) == 0 and len(gas_raw) == 0:
            _LOGGER.debug(
                "Empty BE market prices response (electricity=%s, gas=%s)",
                len(electricity_raw),
                len(gas_raw),
            )
            return cls(
                electricity=PriceData([], energy_type="electricity"),
                gas=PriceData([], energy_type="gas"),
                energy_country=energy_country,
            )

        electricity_price_data = PriceData(electricity_raw, energy_type="electricity")
        gas_price_data = PriceData(gas_raw, energy_type="gas")

        return cls(electricity=electricity_price_data, gas=gas_price_data, energy_country=energy_country)

    @classmethod
    def from_be_dict(cls, data: dict[str, object]) -> MarketPrices:
        """
        Create MarketPrices instance from BE market prices dict.

        Args:
            data: Dictionary with market prices data in BE format.

        Returns:
            MarketPrices instance populated from the provided dict.

        # NOTE:
        # This method only validates and extracts raw BE payload.
        # Normalization is handled in the coordinator layer.
        """
        energy_country = "BE"
        _LOGGER.debug("BE Market Prices keys: %s", list(data.keys()))

        # Defensive: if empty data, return empty PriceData
        if not data:
            return cls(
                electricity=PriceData([], energy_type="electricity"),
                gas=PriceData([], energy_type="gas"),
                energy_country=energy_country,
            )

        _LOGGER.debug("BE Market Prices data: %s", data)

        if data.get("errors"):
            raise RequestException(cls._extract_error(data, "Unknown API error"))

        root = data.get("data")
        if not isinstance(root, dict):
            raise RequestException("Missing 'data' in BE response")

        _LOGGER.debug("BE Market Prices root: %s", root)

        market_prices = root.get("marketPrices")
        _LOGGER.debug("Type of payload data: %s", type(market_prices))
        if not isinstance(market_prices, dict):
            raise RequestException("Missing 'marketPrices' in BE response")

        _LOGGER.debug("BE Market Prices payload: %s", market_prices)

        electricity_raw = market_prices.get("electricityPrices", [])

        if not isinstance(electricity_raw, list):
            _LOGGER.warning("electricityPrices is not a list: %s", type(electricity_raw))
            electricity_raw = []

        gas_raw = market_prices.get("gasPrices", [])

        if not isinstance(gas_raw, list):
            _LOGGER.warning("gasPrices is not a list: %s", type(gas_raw))
            gas_raw = []

        if len(electricity_raw) == 0 and len(gas_raw) == 0:
            _LOGGER.debug(
                "Empty BE market prices response (electricity=%s, gas=%s)",
                len(electricity_raw),
                len(gas_raw),
            )
            return cls(
                electricity=PriceData([], energy_type="electricity"),
                gas=PriceData([], energy_type="gas"),
                energy_country=energy_country,
            )

        # Construct PriceData for electricity and gas similarly to other methods
        electricity_price_data = PriceData(electricity_raw, energy_type="electricity")
        gas_price_data = PriceData(gas_raw, energy_type="gas")

        return cls(electricity=electricity_price_data, gas=gas_price_data, energy_country=energy_country)

    @classmethod
    def from_userprices_dict(cls, data: dict[str, object], energy_country: str) -> MarketPrices:
        """Parse the response from the marketPrices query."""
        _LOGGER.debug("User Prices %s", data)

        if not data:
            return cls(
                electricity=PriceData([], energy_type="electricity"),
                gas=PriceData([], energy_type="gas"),
                energy_country=energy_country,
            )

        error = cls._extract_error(data, None)
        if error:
            if "No marketprices found" in error:
                _LOGGER.debug("No user prices available yet: %s", error)
                return cls(
                    electricity=PriceData([], "electricity"),
                    gas=PriceData([], "gas"),
                    energy_country=energy_country,
                )
            raise RequestException(error)

        if data.get("errors"):
            raise RequestException(cls._extract_error(data, "Unknown API error"))

        # Extract the payload from the data
        root = data.get("data")
        if not isinstance(root, dict):
            raise RequestException("Missing 'data' in response")

        # Get customer market prices from the payload
        customer_market_prices = root.get("customerMarketPrices")
        _LOGGER.debug("Type of payload data: %s", type(customer_market_prices))
        if not isinstance(customer_market_prices, dict):
            raise RequestException("Missing 'customerMarketPrices' in response")

        electricity_raw = customer_market_prices.get("electricityPrices", [])
        if not isinstance(electricity_raw, list):
            _LOGGER.warning("electricityPrices is not a list: %s", type(electricity_raw))
            electricity_raw = []

        gas_raw = customer_market_prices.get("gasPrices", [])
        if not isinstance(gas_raw, list):
            _LOGGER.warning("gasPrices is not a list: %s", type(gas_raw))
            gas_raw = []

        if len(electricity_raw) == 0 and len(gas_raw) == 0:
            _LOGGER.debug(
                "Empty user market prices response (electricity=%s, gas=%s)",
                len(electricity_raw),
                len(gas_raw),
            )
            return cls(
                electricity=PriceData([], energy_type="electricity"),
                gas=PriceData([], energy_type="gas"),
                energy_country=energy_country,
            )

        return cls(
            electricity=PriceData(electricity_raw, energy_type="electricity"),
            gas=PriceData(gas_raw, energy_type="gas"),
            energy_country=energy_country,
        )

    @staticmethod
    def _extract_error(data: dict[str, object], default: str) -> str:
        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                return str(first.get("message", default))
        return default


@dataclass
class Session:
    """A trading session for a battery."""

    date: datetime
    status: str
    # trading_result: float
    trade_index: int | None
    result: float
    cumulative_result: float
    cumulative_trading_result: float

    @staticmethod
    def from_dict(payload: dict[str, object]) -> SmartBatterySessions.Session:
        """Parse the sessions payload from the SmartBatterySessions query result."""
        _LOGGER.debug("🔁 Parsing SmartBatterySessions.Session response: %s", payload)

        try:
            return SmartBatterySessions.Session(
                date=datetime.fromisoformat(payload["date"]).astimezone(UTC),
                status=str(payload["status"]),
                trade_index=payload.get("tradeIndex"),
                result=float(payload["result"]),
                # trading_result=float(payload["tradingResult"]),
                cumulative_result=float(payload["cumulativeResult"]),
                cumulative_trading_result=float(payload["cumulativeTradingResult"]),
            )
        except KeyError as exc:
            raise RequestException(f"Missing expected field in session: {exc}") from exc
        except ValueError as exc:
            raise RequestException(f"Invalid data format in session payload: {exc}") from exc


# @dataclass
@dataclass(slots=True)
class SmartBatteries:
    """Container for multiple smart batteries."""

    batteries: list[SmartBattery] = field(default_factory=list)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> SmartBatteries:
        """Parse the response from the smartBatteries query."""

        if not data:
            _LOGGER.debug("No data found in smart batteries response.")
            return SmartBatteries()

        _LOGGER.debug("SmartBatteries %s", data)

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        payload = data.get("smartBatteries")
        if not payload:
            raise RequestException("Unexpected response")
        if not isinstance(payload, list):
            raise RequestException("Expected 'smartBatteries' to be a list.")

        return SmartBatteries(
            batteries=[SmartBattery.from_dict(smart_battery) for smart_battery in payload],
        )

    @classmethod
    def from_list(cls, data: list[dict[str, object]] | None) -> SmartBatteries:
        """Create SmartBatteries from API response list."""

        if data is None:
            return cls(batteries=[])

        if not isinstance(data, list):
            raise ValueError("SmartBatteries data must be a list")

        batteries: list[SmartBattery] = []

        for item in data:
            if not isinstance(item, dict):
                _LOGGER.debug("Skipping invalid smart battery entry: %s", item)
                continue

            try:
                batteries.append(SmartBattery.from_dict(item))
            except Exception as err:
                _LOGGER.debug(
                    "Failed to parse smart battery entry: %s",
                    err,
                )

        return cls(batteries=batteries)


@dataclass(slots=True)
class SmartBatterySettings:
    """Configuration settings for a smart battery."""

    battery_mode: str | None = None
    created_at: datetime | None = None
    imbalance_trading_strategy: str | None = None
    self_consumption_trading_allowed: bool | None = None
    self_consumption_trading_threshold_price: float | None = None
    updated_at: datetime | None = None

    @classmethod
    def from_dict(
        cls,
        data: dict[str, object] | None,
    ) -> SmartBatterySettings | None:
        """
        Create a SmartBatterySettings instance from API data.

        Args:
            data: API response data.

        Returns:
            Parsed SmartBatterySettings instance.
        """

        if not data:
            return None

        return cls(
            battery_mode=(str(data["batteryMode"]) if data.get("batteryMode") is not None else None),
            imbalance_trading_strategy=(
                str(data["imbalanceTradingStrategy"]) if data.get("imbalanceTradingStrategy") is not None else None
            ),
            self_consumption_trading_allowed=(
                bool(data["selfConsumptionTradingAllowed"])
                if data.get("selfConsumptionTradingAllowed") is not None
                else None
            ),
            self_consumption_trading_threshold_price=(
                float(data["selfConsumptionTradingThresholdPrice"])
                if data.get("selfConsumptionTradingThresholdPrice") is not None
                else None
            ),
            created_at=(
                datetime.fromisoformat(data["createdAt"].replace("Z", _UTC_SUFFIX)).astimezone(UTC)
                if data.get("createdAt") is not None
                else None
            ),
            updated_at=(
                datetime.fromisoformat(data["updatedAt"].replace("Z", _UTC_SUFFIX)).astimezone(UTC)
                if data.get("updatedAt") is not None
                else None
            ),
        )


@dataclass
class SmartBatterySummary:
    """Data representation of a smart battery session summary."""

    last_known_state_of_charge: int
    last_known_status: str
    last_update: datetime
    total_result: float

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SmartBatterySummary:
        """
        Create a SmartBatterySummary from a dictionary.

        Args:
            data: Dictionary containing smart battery summary fields.

        Returns:
            SmartBatterySummary: Parsed dataclass instance.

        Raises:
            ValueError: If 'lastUpdate' is missing or invalid.
        """
        try:
            last_update = datetime.fromisoformat(data["lastUpdate"].replace("Z", _UTC_SUFFIX)).astimezone(UTC)
        except (KeyError, ValueError) as e:
            raise ValueError("Invalid or missing 'lastUpdate' in smartBatterySummary") from e

        return cls(
            last_known_state_of_charge=data.get("lastKnownStateOfCharge", 0),
            last_known_status=data.get("lastKnownStatus", ""),
            last_update=last_update,
            total_result=data.get("totalResult", 0.0),
        )


@dataclass(slots=True)
class SmartBattery:
    """Representation of a Frank Energie smart battery."""

    """
    Core smart battery device data.

    Attributes:
        brand: Manufacturer or brand of the battery.
        capacity: Total storage capacity in kWh.
        external_reference: External identifier used by the provider or platform.
        id: Unique identifier of the battery.
        max_charge_power: Maximum charging power in kW.
        max_discharge_power: Maximum discharging power in kW.
        provider: Name of the service provider.
        created_at: Datetime the battery was registered (must be timezone-aware).
        updated_at: Datetime the battery was last updated (must be timezone-aware).
        settings: Optional battery configuration settings.
        sessions: List of usage sessions or historical interactions.
    """

    id: str
    brand: str | None = None
    capacity: float | None = None
    external_reference: str | None = None
    max_charge_power: float | None = None
    max_discharge_power: float | None = None
    provider: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    settings: SmartBatterySettings | None = None
    summary: SmartBatterySummary | None = None

    def __post_init__(self):
        # Ensure datetime fields are timezone-aware if provided
        if self.created_at and self.created_at.tzinfo is None:
            self.created_at = self.created_at.replace(tzinfo=UTC)
        if self.updated_at and self.updated_at.tzinfo is None:
            self.updated_at = self.updated_at.replace(tzinfo=UTC)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SmartBattery:
        """Create SmartBattery instance from API response."""

        if not isinstance(data, dict):
            raise ValueError("SmartBattery data must be a dictionary")

        device_id = data.get("id")

        if not isinstance(device_id, str) or not device_id:
            raise ValueError("SmartBattery 'id' is missing or invalid")

        settings_data = data.get("settings")

        settings = SmartBatterySettings.from_dict(settings_data) if isinstance(settings_data, dict) else None

        def _to_float(value: object) -> float | None:
            if value is None:
                return None
            try:
                return float(value)
            except (TypeError, ValueError):
                _LOGGER.debug("Invalid float value for battery %s: %s", device_id, value)
                return None

        def _parse_datetime(value: object) -> datetime | None:
            if isinstance(value, datetime):
                return value.astimezone(UTC)
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value.replace("Z", _UTC_SUFFIX)).astimezone(UTC)
                except ValueError:
                    _LOGGER.debug("Invalid datetime value for battery %s: %s", device_id, value)
            return None

        return cls(
            id=device_id,
            brand=data.get("brand"),
            capacity=_to_float(data.get("capacity")),
            external_reference=data.get("externalReference"),
            provider=data.get("provider"),
            max_charge_power=_to_float(data.get("maxChargePower")),
            max_discharge_power=_to_float(data.get("maxDischargePower")),
            created_at=_parse_datetime(data.get("createdAt")),
            updated_at=_parse_datetime(data.get("updatedAt")),
            settings=settings,
        )

    @classmethod
    def from_dict_list(cls, items: list[object]) -> list[SmartBattery]:
        """Convert a list of dicts or existing SmartBattery instances into SmartBattery objects."""
        return [cls.from_dict(item) if isinstance(item, dict) else item for item in items]


@dataclass
class SmartBatterySession:
    """A trading session for a smart battery."""

    date: date
    cumulative_result: float | None
    result: float | None
    status: str
    trade_index: int | None = None

    @staticmethod
    def from_dict(payload: dict[str, Any]) -> SmartBatterySession:
        """Parse the session payload from SmartBatterySessions."""
        _LOGGER.debug("🔁 Parsing SmartBatterySession: %s", payload)
        try:
            return SmartBatterySession(
                date=datetime.fromisoformat(payload["date"]).astimezone(UTC),
                cumulative_result=_safe_float(payload.get("cumulativeResult")),
                result=_safe_float(payload.get("result")),
                status=payload["status"],
                trade_index=payload.get("tradeIndex"),
            )
        except KeyError as exc:
            raise ValueError(f"Missing expected field in session: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid data format in session payload: {exc}") from exc


@dataclass
class SmartBatterySessions:
    """Collection of smart battery trading sessions."""

    device_id: str
    fairuse_policy_verified: bool
    period_start_date: datetime | None
    period_end_date: datetime | None
    period_trade_index: int | None
    period_trading_result: float | None
    trading_result: float | None
    period_total_result: float | None
    period_imbalance_result: float | None
    period_epex_result: float | None
    period_frank_slim: float | None
    sessions: list[SmartBatterySession]
    # total_trading_result: float

    @staticmethod
    def from_dict(data: dict[str, Any]) -> SmartBatterySessions:
        """Parse the response from the SmartBatterySessions query."""
        _LOGGER.debug("🔁 Parsing SmartBatterySessions response: %s", data)

        if errors := data.get("errors"):
            raise RequestException(errors[0]["message"])

        payload = data.get("data")
        if not payload:
            raise RequestException("Unexpected response")

        if not isinstance(payload, Mapping):
            raise RequestException("Missing 'data' in SmartBatterySessions response")

        smart_battery_session_data = payload.get("smartBatterySessions")
        if not isinstance(smart_battery_session_data, Mapping):
            raise RequestException("Missing 'smartBatterySessions' in response")

        _LOGGER.debug("SmartBatterySessions data: %s", smart_battery_session_data)

        return SmartBatterySessions(
            device_id=smart_battery_session_data.get("deviceId"),
            fairuse_policy_verified=smart_battery_session_data.get("fairusePolicyVerified", False),
            period_start_date=_parse_iso_datetime(smart_battery_session_data.get("periodStartDate")),
            period_end_date=_parse_iso_datetime(smart_battery_session_data.get("periodEndDate")),
            period_trade_index=smart_battery_session_data.get("periodTradeIndex", None),
            period_trading_result=_safe_float(smart_battery_session_data.get("periodTradingResult")),
            trading_result=_safe_float(smart_battery_session_data.get("tradingResult")),
            period_total_result=_safe_float(smart_battery_session_data.get("periodTotalResult")),
            period_imbalance_result=_safe_float(smart_battery_session_data.get("periodImbalanceResult")),
            period_epex_result=_safe_float(smart_battery_session_data.get("periodEpexResult")),
            period_frank_slim=_safe_float(smart_battery_session_data.get("periodFrankSlim")),
            sessions=[
                SmartBatterySession.from_dict(session) for session in smart_battery_session_data.get("sessions", [])
            ],
        )

    def __iter__(self) -> Iterator:
        return iter(self.sessions)

    def __len__(self) -> int:
        return len(self.sessions)

    def __getitem__(self, index: int) -> SmartBatterySession:
        return self.sessions[index]

    # def __str__(self) -> str:
    #     return f"SmartBatterySessions({self.device_id}, {len(self.sessions)} sessions, total_result={self.total_trading_result})"


@dataclass
class SmartBatteryDetails:
    """Complete smart battery data including configuration and summary."""

    smart_battery: SmartBattery
    smart_battery_summary: SmartBatterySummary

    @staticmethod
    def from_dict(data: dict[str, Any]) -> SmartBatteryDetails:
        """Parse SmartBatteryDetails from a raw dictionary."""

        sb_data = data.get("smartBattery", {})

        if not sb_data:
            raise ValueError("No smart battery data found")

        _LOGGER.debug("SmartBatteryDetails %s", sb_data)

        settings_data = sb_data.get("settings", {})
        _LOGGER.debug("SmartBatterySettings %s", settings_data)
        if not settings_data:
            _LOGGER.warning("No settings data found in smart battery data")
            settings_data = {}

        smart_battery_settings = SmartBatterySettings(
            battery_mode=settings_data.get("batteryMode", ""),
            imbalance_trading_strategy=settings_data.get("imbalanceTradingStrategy", ""),
            self_consumption_trading_allowed=settings_data.get("selfConsumptionTradingAllowed", False),
            self_consumption_trading_threshold_price=settings_data.get("selfConsumptionTradingThresholdPrice"),
        )

        smart_battery = SmartBattery(
            brand=sb_data.get("brand", ""),
            capacity=sb_data.get("capacity", 0.0),
            id=sb_data.get("id", ""),
            settings=smart_battery_settings,
        )

        summary_data = data.get("smartBatterySummary", {})
        # last_update = datetime.fromisoformat(summary_data["lastUpdate"].replace("Z", "+00:00"))

        smart_battery_summary = SmartBatterySummary.from_dict(summary_data)

        return SmartBatteryDetails(smart_battery=smart_battery, smart_battery_summary=smart_battery_summary)


@dataclass
class old_SmartBatteryDetails:
    """Complete smart battery data including configuration and summary."""

    smart_battery: SmartBattery
    smart_battery_summary: SmartBatterySummary
    # smart_battery_settings: SmartBatterySettings | None = None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> SmartBatteryDetails:
        """Parse SmartBatteryDetails from a raw dictionary."""

        sb_data = data.get("smartBattery", {})

        if not sb_data:
            raise ValueError("No smart battery data found")

        _LOGGER.debug("SmartBatteryDetails %s", sb_data)

        settings_data = sb_data.get("settings", {})
        _LOGGER.debug("SmartBatterySettings %s", settings_data)
        if not settings_data:
            _LOGGER.warning("No settings data found in smart battery data")
            settings_data = {}

        smart_battery_settings = SmartBatterySettings(
            battery_mode=settings_data.get("batteryMode", ""),
            imbalance_trading_strategy=settings_data.get("imbalanceTradingStrategy", ""),
            self_consumption_trading_allowed=settings_data.get("selfConsumptionTradingAllowed", False),
            self_consumption_trading_threshold_price=settings_data.get("selfConsumptionTradingThresholdPrice"),
        )

        created_at_str = sb_data.get("createdAt")
        updated_at_str = sb_data.get("updatedAt")
        created_at_str = sb_data.get("created_at")
        updated_at_str = sb_data.get("updated_at")
        _LOGGER.debug("createdAttttt: %s, updatedAt: %s", created_at_str, updated_at_str)

        try:
            created_at = datetime.fromisoformat(created_at_str).astimezone(UTC) if created_at_str else None
        except Exception:
            _LOGGER.warning("Invalid or missing 'createdAt' in smart battery data: %s", created_at_str)
            created_at = None

        try:
            updated_at = datetime.fromisoformat(updated_at_str).astimezone(UTC) if updated_at_str else None
        except Exception:
            _LOGGER.warning("Invalid or missing 'updatedAt' in smart battery data: %s", updated_at_str)
            updated_at = None

        smart_battery = SmartBattery(
            brand=sb_data.get("brand", ""),
            capacity=sb_data.get("capacity", 0.0),
            external_reference=sb_data.get("externalReference", ""),
            id=sb_data.get("id", ""),
            settings=smart_battery_settings,
            max_charge_power=sb_data.get("maxChargePower", 0.0),
            max_discharge_power=sb_data.get("maxDischargePower", 0.0),
            provider=sb_data.get("provider", ""),
            updated_at=updated_at,
            created_at=created_at,
            sessions=[SmartBatterySession.from_dict(session) for session in sb_data.get("sessions", [])],
        )

        summary_data = data.get("smartBatterySummary", {})

        smart_battery_summary = SmartBatterySummary.from_dict(summary_data)

        return SmartBatteryDetails(smart_battery=smart_battery, smart_battery_summary=smart_battery_summary)


def parse_utc_isoformat(value: str) -> datetime:
    """Convert ISO8601 datetime string to UTC-aware datetime."""
    return datetime.fromisoformat(value.replace("Z", _UTC_SUFFIX)).astimezone(UTC)


def parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return parse_utc_isoformat(value)
        except (ValueError, TypeError):
            _LOGGER.warning("Invalid datetime string: %s", value)
    return None


@dataclass
class BatterySessionSummary:
    active: bool
    charge_energy: float
    discharge_energy: float
    updated_at: str | datetime | None = None

    def __post_init__(self) -> None:
        if isinstance(self.updated_at, str):
            try:
                self.updated_at = parse_datetime(self.updated_at)
            except ValueError:
                _LOGGER.warning("Invalid updated_at format: %s", self.updated_at)
                self.updated_at = None


@dataclass
class BatteryEntityGroup:
    """
    Data representation of a battery entity group.

    Attributes:
        id: Unique identifier of the battery group.
        name: Human-readable name of the battery group.
        battery_ids: List of associated battery device IDs.
        created_at: Datetime when this group was created.
        updated_at: Datetime when this group was last updated.
        mode_sensor: Entity representing the battery mode.
        soc_sensor: Entity representing the state of charge.
        result_sensors: List of result sensor data.
    """

    id: str
    name: str
    battery_ids: list[str]
    created_at: datetime
    updated_at: datetime
    mode_sensor: Any
    soc_sensor: Any
    result_sensors: list[BatteryEntityGroup.ResultSensor] = field(default_factory=list)

    @dataclass
    class ResultSensor:
        """
        Representation of an individual result sensor within a battery entity group.

        Attributes:
            type: Type of result (e.g., 'nettoresultaat').
            entity: Home Assistant entity representing the result.
        """

        type: str
        entity: Any

        @classmethod
        def from_dict(cls, data: dict[str, Any]) -> BatteryEntityGroup.ResultSensor:
            """
            Create a ResultSensor from a dictionary.

            Args:
                data: Dictionary with result sensor data.

            Returns:
                ResultSensor instance.
            """
            return cls(
                type=data["type"],
                entity=data["entity"],
            )

        def to_dict(self) -> dict[str, Any]:
            """
            Serialize ResultSensor to a dictionary.

            Returns:
                Dictionary representation of the result sensor.
            """
            return {
                "type": self.type,
                "entity": self.entity,
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BatteryEntityGroup:
        """
        Create a BatteryEntityGroup from a dictionary.

        Args:
            data: Dictionary containing battery entity group fields.

        Returns:
            BatteryEntityGroup instance.
        """
        try:
            created_at = datetime.fromisoformat(data["createdAt"]).astimezone(UTC)
            updated_at = datetime.fromisoformat(data["updatedAt"]).astimezone(UTC)
        except Exception as exc:
            raise ValueError("Invalid datetime format in 'createdAt' or 'updatedAt'") from exc

        return cls(
            id=data["id"],
            name=data["name"],
            battery_ids=data["batteryIds"],
            created_at=created_at,
            updated_at=updated_at,
            mode_sensor=data.get("modeSensor"),
            soc_sensor=data.get("socSensor"),
            result_sensors=[cls.ResultSensor.from_dict(sensor) for sensor in data.get("resultSensors", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize BatteryEntityGroup to a dictionary.

        Returns:
            Dictionary representation of the battery entity group.
        """
        return {
            "id": self.id,
            "name": self.name,
            "batteryIds": self.battery_ids,
            "createdAt": self.created_at.isoformat(),
            "updatedAt": self.updated_at.isoformat(),
            "modeSensor": self.mode_sensor,
            "socSensor": self.soc_sensor,
            "resultSensors": [sensor.to_dict() for sensor in self.result_sensors],
        }


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value.rstrip("Z"))
        return dt.replace(tzinfo=ZoneInfo("UTC"))
    except ValueError as err:
        raise ValueError(f"Invalid datetime string: {value}") from err


def test_parse_datetime(value: object) -> datetime | None:
    """Parse a datetime string into a timezone-aware datetime object (UTC).

    Handles:
    - ISO 8601 strings
    - Strings ending with 'Z' as UTC
    - Timezone-naive input defaulting to UTC

    Returns None if value is None.
    Raises ValueError on invalid input.
    """
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"Expected string for datetime parsing, got: {type(value).__name__}")

    try:
        dt = parse_datetime(value)
    except (ValueError, TypeError) as err:
        _LOGGER.debug("Failed to parse datetime string '%s': %s", value, err)
        raise ValueError(f"Invalid datetime string: {value}") from err

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))

    return dt


def battery_group_to_extra_state_attributes(group: BatteryEntityGroup) -> dict[str, Any]:
    """
    Convert a BatteryEntityGroup instance into a dictionary suitable for use
    in Home Assistant's extra_state_attributes.

    Args:
        group: The BatteryEntityGroup instance.

    Returns:
        A dictionary representing extra state attributes.
    """
    return {
        "battery_group_id": group.id,
        "battery_group_name": group.name,
        "battery_ids": group.battery_ids,
        "created_at": group.created_at.isoformat(),
        "updated_at": group.updated_at.isoformat(),
        "mode_sensor": group.mode_sensor,
        "soc_sensor": group.soc_sensor,
        "result_sensors": [
            {
                "type": sensor.type,
                "entity": sensor.entity,
            }
            for sensor in group.result_sensors
        ],
    }


@dataclass
class SmartPvSystemPanelGroup(DictLikeMixin):
    """Represents a panel group (dakvlak) of a smart PV system."""

    id: str
    position: int | None
    azimuth: int | None
    tilt: int | None
    capacity_kwp: float | None
    annual_kwh: int | None
    panel_count: int | None
    installation_date: datetime | None

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SmartPvSystemPanelGroup:
        return cls(
            id=data.get("id"),
            position=data.get("position"),
            azimuth=data.get("azimuth"),
            tilt=data.get("tilt"),
            capacity_kwp=float(data["capacityKwp"]) if data.get("capacityKwp") is not None else None,
            annual_kwh=int(data["annualKwh"]) if data.get("annualKwh") is not None else None,
            panel_count=int(data["panelCount"]) if data.get("panelCount") is not None else None,
            installation_date=_parse_datetime(data.get("installationDate")) if data.get("installationDate") else None,
        )


@dataclass
class SmartPvSystem(DictLikeMixin):
    """Represents a single Frank Energie smart PV system."""

    id: str
    brand: str
    connection_ean: str
    created_at: datetime
    deleted_at: datetime | None
    display_name: str | None
    external_reference: str
    inverter_serial_numbers: list[str]
    model: str | None
    onboarding_status: str
    provider: str
    steering_status: str
    updated_at: datetime
    panel_groups: list[SmartPvSystemPanelGroup]

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SmartPvSystem:
        return cls(
            id=data["id"],
            brand=data["brand"],
            connection_ean=data["connectionEAN"],
            created_at=_parse_datetime(data["createdAt"]),
            deleted_at=_parse_datetime(data.get("deletedAt")),
            display_name=data.get("displayName"),
            external_reference=data["externalReference"],
            inverter_serial_numbers=data.get("inverterSerialNumbers") or [],
            model=data.get("model"),
            onboarding_status=data["onboardingStatus"],
            provider=data["provider"],
            steering_status=data["steeringStatus"],
            updated_at=_parse_datetime(data["updatedAt"]),
            panel_groups=[SmartPvSystemPanelGroup.from_dict(v) for v in data.get("SmartPvSystemPanelGroups", [])]
            if isinstance(data.get("SmartPvSystemPanelGroups"), list)
            else [],
        )


@dataclass
class old_SmartPvSystems(DictLikeMixin):
    """Represents a collection of smart PV systems."""

    systems: list[SmartPvSystem]

    @classmethod
    def from_dict(cls, response: dict[str, object]) -> SmartPvSystems:
        if not response:
            return cls(systems=[])
        pv_dicts = response.get("data", {}).get("smartPvSystems", [])
        systems = [SmartPvSystem.from_dict(v) for v in pv_dicts if isinstance(v, dict)]
        return cls(systems=systems)


@dataclass
class SmartPvSystems:
    """Represents a collection of smart PV systems."""

    systems: list[SmartPvSystem]

    @classmethod
    def from_dict(cls, response: dict[str, object] | None) -> SmartPvSystems:
        if not response:
            return cls(systems=[])
        data = response.get("data") or {}
        pv_dicts = data.get("smartPvSystems") or []
        return cls(systems=[SmartPvSystem.from_dict(v) for v in pv_dicts if isinstance(v, dict)])

    def __bool__(self) -> bool:
        return bool(self.systems)


@dataclass
class SmartPvSystemSummary(DictLikeMixin):
    """Real-time summary data for a specific PV system."""

    operational_status: str
    operational_status_timestamp: datetime
    steering_status: str
    total_bonus: float | None
    total_result: float | None

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SmartPvSystemSummary:
        payload = data.get("data", {}).get("smartPvSystemSummary") or data
        return cls(
            operational_status=payload["operationalStatus"],
            operational_status_timestamp=_parse_datetime(payload["operationalStatusTimestamp"]),
            steering_status=payload["steeringStatus"],
            total_bonus=float(payload["totalBonus"]) if payload.get("totalBonus") is not None else None,
            total_result=float(payload["totalResult"]) if payload.get("totalResult") is not None else None,
        )


@dataclass
class UserSmartFeedInStatus(DictLikeMixin):
    """Smart feed-in service status."""

    has_accepted_terms: bool
    is_activated: bool
    is_app_onboarding_available: bool
    is_available_in_country: bool
    user_created_at: datetime
    user_id: str

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> UserSmartFeedInStatus | None:
        """Parse the ``UserSmartFeedIn`` GraphQL response.

        Returns ``None`` when the API reports no feed-in contract for this
        user (i.e. ``userSmartFeedIn`` is ``null`` in the response).  We do
        NOT attempt a feature-flag pre-flight check before calling this
        endpoint because there is no field in the user or connection data that
        reliably indicates feed-in eligibility.  Returning ``None`` here is
        the correct sentinel value; the coordinator treats it as "feature not
        available for this user" without logging an error.
        """
        if errors := data.get("errors"):
            message = (
                errors[0].get("message")
                if isinstance(errors, list) and errors and isinstance(errors[0], dict)
                else "Unknown error"
            )
            raise RequestException(str(message))

        root = data.get("data")
        if not isinstance(root, Mapping):
            raise RequestException("Missing 'data' in userSmartFeedIn response")

        payload = root.get("userSmartFeedIn")
        if payload is None:
            # API returns null for users without a feed-in contract.
            return None

        if not isinstance(payload, Mapping):
            raise RequestException("Unexpected userSmartFeedIn payload type")

        return cls(
            has_accepted_terms=payload["hasAcceptedTerms"],
            is_activated=payload["isActivated"],
            is_app_onboarding_available=payload["isAppOnboardingAvailable"],
            is_available_in_country=payload["isAvailableInCountry"],
            user_created_at=_parse_datetime(payload["userCreatedAt"]),
            user_id=payload["userId"],
        )


@dataclass
class FeedInSession(DictLikeMixin):
    """Represents a single feed-in session."""

    bonus: float
    cumulative_bonus: float
    date: str
    status: str
    volume: float

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> FeedInSession:
        return cls(
            bonus=float(data.get("bonus", 0.0)),
            cumulative_bonus=float(data.get("cumulativeBonus", 0.0)),
            date=data["date"],
            status=data["status"],
            volume=float(data.get("volume", 0.0)),
        )


@dataclass
class SmartFeedInSessionData(DictLikeMixin):
    """Solar feed-in session data over a period."""

    period_bonus: float
    period_end_date: str
    period_start_date: str
    period_volume: float
    sessions: list[FeedInSession]

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SmartFeedInSessionData:
        payload = data.get("data", {}).get("smartFeedInSessions") or data
        sessions = [FeedInSession.from_dict(s) for s in (payload.get("sessions") or [])]
        return cls(
            period_bonus=float(payload.get("periodBonus", 0.0)),
            period_end_date=payload["periodEndDate"],
            period_start_date=payload["periodStartDate"],
            period_volume=float(payload.get("periodVolume", 0.0)),
            sessions=sessions,
        )
