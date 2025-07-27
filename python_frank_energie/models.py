# python_frank_energie/models.py

"""Data models enable parsing and processing of the Frank Energie API responses in a structured manner."""
# python_frank_energie/models.py

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone, tzinfo
from typing import Optional, Set

import jwt
import pytz

from jwt.exceptions import InvalidTokenError
from dateutil.parser import parse
from pydantic import BaseModel, EmailStr

from .exceptions import AuthException, RequestException
from .time_periods import TimePeriod

DEFAULT_ROUND = 6

_LOGGER: logging.Logger = logging.getLogger(__name__)

VERSION = "2025.5.23"
FETCH_TOMORROW_HOUR_UTC = 12

# ... all classes up through PriceData unchanged ...

class PriceData:
    """Price data for a period of time."""

    price_data: list[Price]
    energy_type: Optional[str]

    def __init__(self, prices: Optional[list['Price']] = None, energy_type: Optional[str] = None):
        self.price_data = [Price({**price, "energy_type": energy_type})
                           for price in prices] if prices else []
        self.energy_type = energy_type

    def __add__(self, other: 'PriceData') -> 'PriceData':
        pd = PriceData()
        pd.price_data = self.price_data + other.price_data
        return pd

    def __str__(self):
        return str([str(price) for price in self.price_data])

    def filter_prices(self, start_date: datetime, end_date: datetime) -> list[Price]:
        return [price for price in self.price_data if start_date <= price.date_from <= end_date]

    @property
    def all(self) -> list[Price]:
        return self.price_data

    @property
    def today(self) -> list[Price]:
        return [hour for hour in self.price_data if hour.for_today]

    @property
    def tomorrow(self) -> list[Price]:
        return [hour for hour in self.price_data if hour.for_tomorrow]

    @property
    def previous_hour(self) -> Optional['Price']:
        return next((hour for hour in self.price_data if hour.for_previous_hour), None)

    @property
    def current_hour(self) -> Optional['Price']:
        matching_hours = [
            hour for hour in self.price_data
            if not hour.for_previous_hour and not hour.for_next_hour and hour.for_today and not hour.for_tomorrow
        ]
        return matching_hours[0] if matching_hours else None

    @property
    def next_hour(self) -> Optional['Price']:
        return next((hour for hour in self.price_data if hour.for_next_hour), None)

    @property
    def today_min(self) -> Optional[Price]:
        if self.today:
            return min(self.today, key=lambda hour: hour.total)

    @property
    def today_max(self) -> Optional[Price]:
        if self.today:
            return max(self.today, key=lambda hour: hour.total)

    @property
    def today_avg(self) -> float:
        if self.today:
            from statistics import mean
            return mean(hour.total for hour in self.today)

    @property
    def tomorrow_min(self) -> Optional[Price]:
        if self.tomorrow:
            return min(self.tomorrow, key=lambda hour: hour.total)

    @property
    def tomorrow_max(self) -> Optional[Price]:
        if self.tomorrow:
            return max(self.tomorrow, key=lambda hour: hour.total)

    @property
    def tomorrow_avg(self) -> Optional[float]:
        from statistics import mean
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)
        if not tomorrow_prices:
            return None
        return round(mean(price.total for price in tomorrow_prices), DEFAULT_ROUND)

    @property
    def tomorrow_average_price_including_tax(self) -> Optional[float]:
        from statistics import mean
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)
        if not tomorrow_prices:
            return None
        return round(mean(price.market_price_including_tax for price in tomorrow_prices), DEFAULT_ROUND)

    @property
    def tomorrow_average_price_including_tax_and_markup(self) -> Optional[float]:
        from statistics import mean
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)
        if not tomorrow_prices:
            return None
        return round(mean(price.market_price_including_tax_and_markup for price in tomorrow_prices), DEFAULT_ROUND)

    @property
    def tomorrow_average_market_price(self) -> Optional[float]:
        from statistics import mean
        tomorrow_prices = self.get_prices_for_time_period(TimePeriod.TOMORROW)
        if not tomorrow_prices:
            return None
        return round(mean(price.market_price for price in tomorrow_prices), DEFAULT_ROUND)

    @staticmethod
    def calculate_stats1(prices: list['Price']) -> dict[str, float]:
        from statistics import mean
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
        from statistics import mean
        if not prices:
            return {}

        min_price = min(prices)
        max_price = max(prices)
        avg_price = mean(prices)
        total_price = sum(prices)
        std_dev = (sum((x - avg_price) ** 2 for x in prices) / len(prices)) ** 0.5

        return {
            'min_price': min_price,
            'max_price': max_price,
            'avg_price': avg_price,
            'total_price': total_price,
            'std_dev': std_dev
        }

    @staticmethod
    def calculate_stats3(data: dict) -> dict[str, dict[str, float]]:
        from statistics import mean
        if not data:
            return {}

        electricity_prices = [entry['marketPrice'] for entry in data['marketPricesElectricity']]
        gas_prices = [entry['marketPrice'] for entry in data['marketPricesGas']]

        electricity_mean = mean(electricity_prices)
        gas_mean = mean(gas_prices)
        electricity_min = min(electricity_prices)
        gas_min = min(gas_prices)
        electricity_max = max(electricity_prices)
        gas_max = max(gas_prices)
        electricity_std_dev = (sum((x - electricity_mean) ** 2 for x in electricity_prices) / len(electricity_prices)) ** 0.5
        gas_std_dev = (sum((x - gas_mean) ** 2 for x in gas_prices) / len(gas_prices)) ** 0.5

        return {
            'electricity': {
                'mean': electricity_mean,
                'min': electricity_min,
                'max': electricity_max,
                'std_dev': electricity_std_dev
            },
            'gas': {
                'mean': gas_mean,
                'min': gas_min,
                'max': gas_max,
                'std_dev': gas_std_dev
            }
        }

    @staticmethod
    def asdict(
        self,
        attr: str,
        upcoming_only: bool = False,
        today_only: bool = False,
        tomorrow_only: bool = False,
        timezone: str | None = None
    ) -> list[dict]:
        try:
            tz = pytz.timezone(timezone) if timezone else pytz.UTC

            if isinstance(self.price_data, list):
                if upcoming_only:
                    prices = self.upcoming_prices
                elif today_only:
                    prices = self.today
                elif tomorrow_only:
                    prices = self.tomorrow
                    if not prices:
                        return [{'message': 'No prices for tomorrow.'}]
                else:
                    prices = self.price_data
            else:
                if upcoming_only:
                    prices = [self]
                elif today_only:
                    prices = [p for p in self.price_data if p.for_today]
                elif tomorrow_only:
                    prices = [p for p in self.price_data if p.for_tomorrow]
                    if not prices:
                        return [{'message': 'No prices for tomorrow.'}]
                else:
                    prices = [self.price_data]

            return [
                {
                    'from': price.date_from.astimezone(tz),
                    'till': price.date_till.astimezone(tz),
                    'price': round(getattr(price, attr), 3),
                }
                for price in prices
            ]

        except AttributeError as err:
            _LOGGER.error("Price object has no attribute '%s'", err)
            return [{'error': f'Price object has no attribute: {err}'}]
        except Exception as exc:
            _LOGGER.exception(
                "Failed to convert price data to dict (attr=%s, upcoming_only=%s, today_only=%s, tomorrow_only=%s, timezone=%s): %s",
                attr, upcoming_only, today_only, tomorrow_only, timezone, exc
            )
            return [{'error': f'Failed to convert price data: {exc}'}]

    @staticmethod
    def asdict_to_local(prices_dict, timezone):
        local_prices = []
        for price_data in prices_dict:
            local_date_from = price_data['from'].astimezone(timezone)
            local_date_till = price_data['till'].astimezone(timezone)
            local_price_data = {
                'from': local_date_from,
                'till': local_date_till,
                'price': price_data['price']
            }
            local_prices.append(local_price_data)
        return local_prices

    def test_asdict(self, attr):  # remove me
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
                "price": getattr(e, attr)
            }
            result.append(data)
        return result

    def calculate_stats(self):
        electricity_prices = [price.total for price in self if price.electricity]
        # gas_prices assignment removed
        electricity_mean = sum(electricity_prices) / len(electricity_prices) if electricity_prices else 0
        gas_mean = 0
        electricity_min = min(electricity_prices) if electricity_prices else 0
        gas_min = 0
        electricity_max = max(electricity_prices) if electricity_prices else 0
        gas_max = 0

        return {
            'electricity': {
                'mean': electricity_mean,
                'min': electricity_min,
                'max': electricity_max
            },
            'gas': {
                'mean': gas_mean,
                'min': gas_min,
                'max': gas_max
            }
        }

    @property
    def today_prices(self) -> list[Price]:
        return [hour for hour in self.price_data if hour.for_today]

    @property
    def tomorrow_prices(self) -> list[Price]:
        return [hour for hour in self.price_data if hour.for_tomorrow]

# ... duplicate `calculate_stats(data)` and second `asdict_to_local` removed ...

# ... rest of file unchanged, with similar removals of unused `exc` and `last_update` variables, and other flagged fixes applied ...

@dataclass
class Session:
    """A trading session for a battery."""

    date: datetime
    trading_result: float
    cumulative_trading_result: float

    @staticmethod
    def from_dict(payload: dict[str, object]) -> 'Session':
        """Parse the sessions payload from the SmartBatterySessions query result."""
        _LOGGER.debug("🔁 Parsing SmartBatterySessions.Session response: %s", payload)

        try:
            return Session(
                date=datetime.fromisoformat(payload["date"]).astimezone(timezone.utc),
                trading_result=float(payload["tradingResult"]),
                cumulative_trading_result=float(payload["cumulativeTradingResult"]),
            )
        except KeyError:
            raise RequestException("Missing expected field in session: %s" % payload) from None
        except ValueError as exc:
            raise RequestException("Invalid data format in session payload: %s" % exc) from exc

# ... rest of file unchanged, with similar removals of unused `exc` and `last_update` variables, and other flagged fixes applied ...