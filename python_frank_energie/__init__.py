"""Frank Energie API library."""
# python_frank_energie/__init__.py
from .domain import CountryCode, Resolution, EnergyType
from .frank_energie import FrankEnergie
from .models import Invoices, MarketPrices, Price, PriceData, PeriodUsageAndCosts
from .authentication import Authentication
from .exceptions import AuthException, ConnectionException, RequestException

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
