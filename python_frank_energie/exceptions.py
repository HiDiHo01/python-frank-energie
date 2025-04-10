"""Exceptions for the Frank Energie API."""

class FrankEnergieException(Exception):
    """Base exception."""

class AuthRequiredException(FrankEnergieException):
    """Authentication required for this request."""

class AuthException(FrankEnergieException):
    """Authentication/login failed."""

class RequestException(FrankEnergieException):
    """Request failed."""

class NoSuitableSitesFoundError(FrankEnergieException):
    """Request failed."""

class FrankEnergieError(Exception):
    """Base class for all FrankEnergie-related errors."""

class LoginError(FrankEnergieException):
    """Raised when login to FrankEnergie fails."""

class NetworkError(FrankEnergieException):
    """Raised for network-related errors in FrankEnergie."""

class SmartTradingNotEnabledException(FrankEnergieException):
    """Exception raised when smart trading is not enabled for the user."""

class SmartChargingNotEnabledException(FrankEnergieException):
    """Exception raised when smart charging is not enabled for the user."""

class ConnectionException(FrankEnergieException):
    """Raised for network-related errors in FrankEnergie."""
