"""Exceptions for the Frank Energie API."""


class FrankEnergieException(Exception):
    """Base exception."""


class AuthRequiredException(FrankEnergieException):
    """Authentication required for this request."""


class AuthException(FrankEnergieException):
    """Authentication/login failed."""


class RequestException(FrankEnergieException):
    """Request failed."""


class RateLimitException(RequestException):
    """Report a rate-limited request and an optional server-provided delay."""

    def __init__(self, operation_name: str, *, retry_after: float | None = None) -> None:
        """Store the operation and Retry-After seconds without scheduling retries."""
        self.operation_name = operation_name
        self.retry_after = retry_after
        super().__init__(f"Frank Energie rate limit exceeded during operation [{operation_name}].")

    def __reduce__(self) -> tuple[object, ...]:
        """Rebuild from the operation name and restore metadata and notes."""
        return type(self), (self.operation_name,), self.__dict__


class NoSuitableSitesFoundError(FrankEnergieException):
    """Request failed."""


class FrankEnergieError(Exception):
    """Base class for all FrankEnergie-related errors."""


class NoMarketPricesAvailableException(RequestException):
    """No market prices are available yet."""


class LoginError(FrankEnergieException):
    """Raised when login to FrankEnergie fails."""


class RefreshTokenInvalidException(AuthException):
    """Raised when the refresh token is no longer valid."""


class NetworkError(FrankEnergieException):
    """Raised for network-related errors in FrankEnergie."""


class SmartTradingNotEnabledException(FrankEnergieException):
    """Exception raised when smart trading is not enabled for the user."""


class SmartChargingNotEnabledException(FrankEnergieException):
    """Exception raised when smart charging is not enabled for the user."""


class SmartBatteryNotFoundException(FrankEnergieException):
    """Exception raised when a smart battery is not found for the user."""


class ConnectionException(FrankEnergieException):
    """Raised for network-related errors in FrankEnergie."""
