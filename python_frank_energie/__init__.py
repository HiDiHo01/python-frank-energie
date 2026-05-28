"""Frank Energie API library."""

# python_frank_energie/__init__.py
from .authentication import Authentication
from .domain import CountryCode, EnergyType, Resolution
from .exceptions import AuthException, ConnectionException, RequestException
from .frank_energie import FrankEnergie
from .models import Invoices, MarketPrices, PeriodUsageAndCosts, Price, PriceData

__version__ = "2026.3.21"

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
