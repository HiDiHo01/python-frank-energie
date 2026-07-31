"""Frank Energie API library."""

# python_frank_energie/__init__.py
from importlib.metadata import PackageNotFoundError, version

from .authentication import Authentication
from .domain import CountryCode, EnergyType, Resolution
from .exceptions import AuthException, ConnectionException, RequestException
from .frank_energie import _DISTRIBUTION_NAME, FrankEnergie
from .models import (
    ContractPriceResolutionChangeResult,
    ContractPriceResolutionState,
    Invoices,
    MarketPrices,
    PeriodUsageAndCosts,
    Price,
    PriceData,
)

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
    # Exceptions
    "AuthException",
    "ConnectionException",
    "RequestException",
]
