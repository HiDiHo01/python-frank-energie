"""Frank Energie API library."""

# python_frank_energie/__init__.py
from importlib.metadata import PackageNotFoundError, version

from .authentication import Authentication
from .domain import CountryCode, EnergyType, Resolution
from .exceptions import (
    AuthException,
    ConnectionException,
    RateLimitException,
    RequestException,
    SmartFeedInNotEnabledException,
)
from .frank_energie import _DISTRIBUTION_NAME, FrankEnergie
from .models import (
    ContractPriceResolutionChangeResult,
    ContractPriceResolutionState,
    Invoices,
    MarketPrices,
    PeriodUsageAndCosts,
    Price,
    PriceData,
    SmartHvac,
    SmartHvacConnectRequest,
    SmartHvacDevice,
    SmartHvacSummary,
)
from .weighted_average_prices import WeightedAveragePriceCategory, WeightedAveragePriceItem, WeightedAveragePrices

try:
    __version__ = version(_DISTRIBUTION_NAME)
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = [
    # Core client
    "FrankEnergie",
    # Authentication
    "Authentication",
    # Domain
    "CountryCode",
    "Resolution",
    "EnergyType",
    # Models
    "ContractPriceResolutionChangeResult",
    "ContractPriceResolutionState",
    "Invoices",
    "MarketPrices",
    "Price",
    "PriceData",
    "PeriodUsageAndCosts",
    "WeightedAveragePriceCategory",
    "WeightedAveragePriceItem",
    "WeightedAveragePrices",
    "SmartHvac",
    "SmartHvacConnectRequest",
    "SmartHvacDevice",
    "SmartHvacSummary",
    # Exceptions
    "AuthException",
    "ConnectionException",
    "RateLimitException",
    "RequestException",
    "SmartFeedInNotEnabledException",
]
