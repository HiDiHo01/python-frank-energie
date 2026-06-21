"""Frank Energie API implementation."""

# python_frank_energie/frank_energie.py
# version 2026.06.10

import asyncio
import logging
import platform
import re
import sys
import time
from datetime import UTC, date, datetime, timedelta
from http import HTTPStatus
from typing import Any, TypeVar

import aiohttp
from aiohttp import ClientError, ClientSession, ClientTimeout

from .exceptions import (
    AuthException,
    AuthRequiredException,
    FrankEnergieException,
    NetworkError,
    RequestException,
    SmartChargingNotEnabledException,
    SmartTradingNotEnabledException,
)
from .models import (
    Authentication,
    ContractPriceResolutionChangeResult,
    ContractPriceResolutionState,
    EnergyConsumption,
    EnodeChargers,
    EnodeVehicle,
    EnodeVehicles,
    Invoices,
    MarketPrices,
    Me,
    MonthInsights,
    MonthSummary,
    PeriodUsageAndCosts,
    Resolution,
    SmartBatteries,
    SmartBattery,
    SmartBatteryDetails,
    SmartBatterySessions,
    SmartBatterySummary,
    SmartHvac,
    SmartPvSystems,
    SmartPvSystemSummary,
    User,
    UserSites,
    UserSmartFeedInStatus,
)

T = TypeVar("T")

_LOGGER = logging.getLogger(__name__)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

VERSION = "2026.6.21"


class FrankEnergieQuery:
    """Represents a GraphQL query for the FrankEnergie API."""

    def __init__(self, query: str, operation_name: str, variables: dict[str, Any] | None = None) -> None:
        if variables is not None and not isinstance(variables, dict):
            raise TypeError("The 'variables' argument must be a dictionary if provided.")

        self.query = query
        self.operation_name = operation_name
        self.variables = variables if variables is not None else {}

    def to_dict(self) -> dict[str, Any]:
        """Convert the query to a dictionary suitable for GraphQL API calls."""
        return {
            "query": self.query,
            "operationName": self.operation_name,
            "variables": self.variables,
        }


def sanitize_query(query: FrankEnergieQuery) -> dict[str, Any]:
    sanitized_query = query.to_dict()
    if "password" in sanitized_query["variables"]:
        sanitized_query["variables"]["password"] = "****"
    return sanitized_query


class FrankEnergie:
    """Frank Energie API client."""

    DATA_URL = "https://frank-graphql-prod.graphcdn.app/"
    # DATA_URL = "https://graphql.frankenergie.nl/"
    RENEW_TOKEN_OPERATIONNAME = "RenewToken"
    AUTH_HEADER_EXEMPT_OPERATIONS = {
        RENEW_TOKEN_OPERATIONNAME,
    }

    def __init__(
        self,
        clientsession: ClientSession | None = None,
        auth_token: str | None = None,
        refresh_token: str | None = None,
        version: str | None = None,
    ) -> None:
        """Initialize the FrankEnergie client."""
        self._session: ClientSession | None = clientsession
        self._close_session: bool = clientsession is None
        self._auth: Authentication | None = None
        self._last_query: FrankEnergieQuery | None = None
        self._last_variables: dict[str, object] | None = None
        self._renew_lock = asyncio.Lock()
        self._site_reference: str | None = None
        self._user_country: str | None = None
        self._resolution: str | None = "PT60M"

        if auth_token or refresh_token:
            self._auth = Authentication(auth_token, refresh_token, version)

    is_smart_charging = False
    is_smart_trading = False

    async def close(self) -> None:
        """Close the client session if it was created internally."""
        if self._close_session and self._session is not None:
            await self._session.close()
            self._session = None
            self._close_session = False

    # NOTE:
    # Authentication lifecycle is documented in docs/authentication.md.
    #
    # Do not make authentication state depend solely on JWT expiration
    # unless automatic token renewal is performed before requests.
    #
    # Access tokens are expected to be renewed via renew_token().
    # Reauthentication should only be required when token renewal fails.
    @property
    def auth(self) -> Authentication | None:
        """Return the current authentication information (deprecated)."""
        _LOGGER.error("Using .auth directly is deprecated. Use .is_authenticated instead.")
        return self._auth

    @property
    def is_authenticated(self) -> bool:
        """Return True when valid authentication tokens are available."""

        return bool(self._auth is not None and self._auth.authToken)

    async def validate_authentication(self) -> bool:
        """Validate the current authentication tokens."""

        if not self.is_authenticated:
            return False

        self._log_token_status()

        try:
            async with self._renew_lock:
                if self._auth is not None and self._auth.is_expired:
                    await self.renew_token()
        except (AuthException, AuthRequiredException):
            return False

        return True

    def _requires_token_refresh(
        self,
        operation_name: str,
    ) -> bool:
        if operation_name == self.RENEW_TOKEN_OPERATIONNAME:
            return False

        if self._auth is None:
            return False

        self._log_token_status()
        return self._auth.is_expired

    def _log_token_status(self) -> None:
        """Log the current token expiry status and if renewal is required."""
        if self._auth is None or not self._auth.expires_at:
            return

        now_utc = datetime.now(UTC)
        remaining = self._auth.expires_at - now_utc
        _LOGGER.debug(
            "Token expiry check: now=%s expires_at=%s remaining=%s",
            now_utc.isoformat(),
            self._auth.expires_at.isoformat(),
            remaining,
        )

        if self._auth.is_expired:
            _LOGGER.debug(
                "Token renewal required: expires_at=%s threshold=%s minutes",
                self._auth.expires_at.isoformat(),
                Authentication.TOKEN_RENEWAL_MARGIN.total_seconds() / 60,
            )

    @staticmethod
    def generate_system_user_agent() -> str:
        """Generate the system user-agent string for API requests."""
        system = platform.system()  # e.g., 'Darwin' for macOS, 'Windows' for Windows
        system_platform = sys.platform  # e.g., 'win32', 'linux', 'darwin'
        release = platform.release()  # OS version (e.g., '10.15.7')
        version = VERSION  # App version

        user_agent = f"FrankEnergie/{version} {system}/{release} {system_platform}"
        return user_agent

    async def _ensure_session(self) -> None:
        """Ensure that a ClientSession is available."""
        if self._session is None:
            self._session = ClientSession()
            self._close_session = True

    async def _query(self, query: FrankEnergieQuery, extra_headers: dict[str, str] | None = None) -> dict[str, object]:
        """Send a query to the FrankEnergie API.

        Args:
            query: The GraphQL query as a dictionary.

        Returns:
            The response from the API as a dictionary.

        Raises:
            NetworkError: If the network request fails.
            FrankEnergieException: If the request fails.
        """
        if not hasattr(query, "to_dict") or not callable(query.to_dict):
            raise TypeError("Query object must implement a to_dict().")

        operation_name = query.operation_name

        if not operation_name:
            raise ValueError("GraphQL operation name must not be empty")

        start = time.monotonic()

        # "User-Agent": self.generate_system_user_agent(), # not working properly
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-graphql-client-version": "4.13.3",
            "x-graphql-client-name": "frank-app",
            "x-graphql-client-os": "ios/26.0.1",
            "skip-graphcdn": "1",
        }

        if self._requires_token_refresh(query.operation_name):
            async with self._renew_lock:
                if self._requires_token_refresh(query.operation_name):
                    _LOGGER.debug("Access token expired; attempting token renewal")
                    await self.renew_token()

        if self._auth is not None and query.operation_name not in self.AUTH_HEADER_EXEMPT_OPERATIONS:
            headers["Authorization"] = f"Bearer {self._auth.authToken}"

        if extra_headers:
            headers.update(extra_headers)

        self._last_query = query
        self._last_variables = query.variables
        operation_name = query.operation_name

        payload: dict[str, object] = query.to_dict()

        _LOGGER.debug(
            "Executing GraphQL operation [%s] with variables: %s",
            operation_name,
            self._last_variables,
        )

        await self._ensure_session()

        timeout = ClientTimeout(total=30)
        try:
            async with self._session.post(self.DATA_URL, json=payload, headers=headers, timeout=timeout) as resp:
                resp.raise_for_status()

                response: dict[str, object] = await resp.json()

            if not response:
                _LOGGER.debug(
                    "Empty API response received for operation [%s]",
                    operation_name,
                )
                return {}

            # _LOGGER.debug("Response body: %s", response)

            self._handle_errors(response, operation_name)

            # print(f"Response status code: {response.status}")
            # print(f"Response headers: {response.headers}")
            # print(f"Response body: {response}")

            duration = time.monotonic() - start
            _LOGGER.debug(
                "GraphQL operation [%s] completed in %.2fs",
                operation_name,
                duration,
            )

            return response

        except TimeoutError as err:
            _LOGGER.error(
                "Frank Energie API timeout during operation [%s]",
                operation_name,
            )
            raise NetworkError("Frank Energie API timeout") from err

        except aiohttp.ClientResponseError as error:
            _LOGGER.error(
                "Frank Energie API error during operation [%s]: %s",
                operation_name,
                error,
            )
            if error.status == HTTPStatus.UNAUTHORIZED:
                raise AuthRequiredException("Authentication required.") from error
            elif error.status == HTTPStatus.FORBIDDEN:
                raise AuthException("Forbidden: Invalid credentials.") from error
            elif error.status == HTTPStatus.BAD_REQUEST:
                raise RequestException("Bad request: Invalid query.") from error
            elif error.status == HTTPStatus.INTERNAL_SERVER_ERROR:
                raise FrankEnergieException("Internal server error.") from error
            else:
                raise FrankEnergieException(f"Unexpected response: {error}") from error
        except ClientError as err:
            _LOGGER.error(
                "Frank Energie HTTP client error during [%s]: %s",
                operation_name,
                err,
            )
            raise NetworkError(f"Frank Energie HTTP error: {err}") from err
        except KeyError as err:
            _LOGGER.error(
                "Unexpected API response structure during [%s]: missing key %s",
                operation_name,
                err,
            )
            raise NetworkError(f"Invalid API response: missing {err}") from err

    def _handle_errors(self, response: dict[str, object], operation_name: str | None = None) -> None:
        """
        Handle common GraphQL error messages and raise specific exceptions when needed.

        Args:
            response: The API response as a dictionary.

        Raises:
            AuthException: For authentication-related errors.
            AuthRequiredException: When authentication is required.
            FrankEnergieException: For unhandled or critical API errors.
        """
        if not response:
            _LOGGER.debug("No response data to handle errors.")
            return

        errors_obj: object | None = response.get("errors")
        if not errors_obj:
            return

        if not isinstance(errors_obj, list):
            _LOGGER.error("Invalid GraphQL error structure: %s", errors_obj)
            raise FrankEnergieException("Invalid GraphQL error structure")

        active_query = operation_name or getattr(self, "_operation_name", "<unknown>")

        for error_obj in errors_obj:
            if not isinstance(error_obj, dict):
                _LOGGER.error("Unexpected GraphQL error entry: %s", error_obj)
                continue

            message_obj: object | None = error_obj.get("message")
            message: str = message_obj if isinstance(message_obj, str) else ""
            path: object | None = error_obj.get("path")
            ext_obj: object | None = error_obj.get("extensions")  # GraphQL extension metadata
            extensions: dict[str, object] | None = ext_obj if isinstance(ext_obj, dict) else None

            # --- Authentication errors ---
            if message == "user-error:password-invalid":
                raise AuthException("Invalid password")
            elif message == "user-error:auth-not-authorised":
                raise AuthException("Not authorized")
            elif message == "user-error:auth-required":
                raise AuthRequiredException("Authentication required")
            elif message == "Graphql validation error":
                log_level = logging.DEBUG if active_query == "SmartHvacStatus" else logging.ERROR
                _LOGGER.log(
                    log_level,
                    "GraphQL validation error - query %s: %s path=%s (response: %s)",
                    active_query,
                    message,
                    path,
                    response,
                )
                raise FrankEnergieException("Request failed: Graphql validation error")

            # --- Expected "no data" cases (not failures) ---
            elif message.startswith("No marketprices found for segment"):
                # Normal scenario, just skip
                continue
            elif message.startswith("No reading dates found for user"):
                # Typical for IN_DELIVERY sites
                continue

            # --- Feature not enabled ---
            elif message == "user-error:smart-trading-not-enabled":
                raise SmartTradingNotEnabledException("Smart trading is not enabled for this user.")
            elif message == "user-error:smart-charging-not-enabled":
                raise SmartChargingNotEnabledException("Smart charging is not enabled for this user.")
            elif message == "user-error:smart-feed-in-not-enabled":
                _LOGGER.debug("Smart fed-in is not enabled for this user.")
                continue

            # --- Other specific messages ---
            elif message == "'Base' niet aanwezig in prijzen verzameling":
                _LOGGER.debug("'Base' niet aanwezig in prijzen verzameling %s.", path)
                continue

            # --- Critical errors ---
            elif message.startswith("No connections found for user"):
                raise FrankEnergieException(f"Request failed: {message}")
            elif message == "request-error:request-not-supported-in-country":
                _LOGGER.error("Request not supported in user's country: %s", error_obj)
                raise FrankEnergieException("Request not supported in the user's country")
            else:
                # --- Unhandled errors ---
                _LOGGER.error("Unhandled GraphQL error message: %s", message)
                _LOGGER.error("Unhandled GraphQL error object: %s", error_obj)

            if extensions:
                _LOGGER.debug("GraphQL extensions: %s", extensions)

    LOGIN_QUERY = """
        mutation Login($email: String!, $password: String!) {
            login(email: $email, password: $password) {
                authToken
                refreshToken
                __typename
            }
            version
            __typename
        }
    """
    LOGIN_OPERATION_NAME = "Login"

    async def login(self, username: str, password: str) -> Authentication | None:
        """Login and retrieve the authentication token.

        Args:
            username: The user's email.
            password: The user's password.

        Returns:
            The authentication information.

        Raises:
            ValueError: If username or password is missing.
            AuthException: If the login fails.
        """
        if not username or not password:
            raise ValueError("Username and password must be provided.")

        query = FrankEnergieQuery(
            self.LOGIN_QUERY,
            self.LOGIN_OPERATION_NAME,
            {"email": username, "password": password},
        )

        try:
            response = await self._query(query)
            if response is None:
                raise AuthException("Login failed. No response received.")

            auth = Authentication.from_dict(response)
            if auth is None:
                raise AuthException("Login failed. Authentication data missing.")

            self._auth = auth
            expires_str = auth.expires_at.isoformat() if auth.expires_at else "unknown/mock"
            _LOGGER.debug(
                "Authentication token updated; expires_at=%s",
                expires_str,
            )
            return auth

        except (asyncio.CancelledError, AuthException):
            raise

        except Exception as err:
            _LOGGER.exception("Login failed")
            raise AuthException("Authentication failed.") from err

    async def renew_token(self) -> Authentication:
        """Renew the authentication token.

        Returns:
            The renewed authentication information.

        Raises:
            AuthRequiredException: If the client is not authenticated.
            AuthException: If the token renewal fails.
        """
        if self._auth is None:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation RenewToken($authToken: String!, $refreshToken: String!) {
                renewToken(authToken: $authToken, refreshToken: $refreshToken) {
                    authToken
                    refreshToken
                }
            }
            """,
            "RenewToken",
            {
                "authToken": self._auth.authToken,
                "refreshToken": self._auth.refreshToken,
            },
        )

        response = await self._query(query)
        self._auth = Authentication.from_dict(response)
        if self._auth:
            expires_str = self._auth.expires_at.isoformat() if self._auth.expires_at else "unknown/mock"
            _LOGGER.debug(
                "Authentication token updated; expires_at=%s",
                expires_str,
            )
        return self._auth

    async def meter_readings(self, site_reference: str) -> EnergyConsumption:
        """Retrieve the meter_readings.

        Args:
            month: The month for which to retrieve the summary. Defaults to the current month.

        Returns:
            The Meter Readings.

        Raises:
            AuthRequiredException: If the client is not authenticated.
            FrankEnergieException: If the request fails.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            query ActualAndExpectedMeterReadings($siteReference: String!) {
            completenessPercentage
            actualMeterReadings {
                date
                consumptionKwh
            }
            expectedMeterReadings {
                date
                consumptionKwh
            }
            }
            """,
            "ActualAndExpectedMeterReadings",
            {"siteReference": site_reference},
        )

        response = await self._query(query)
        return EnergyConsumption.from_dict(response)

    async def month_summary(self, site_reference: str) -> MonthSummary:
        """Retrieve the month summary for the specified month.

        Args:
            month: The month for which to retrieve the summary. Defaults to the current month.

        Returns:
            The month summary information.

        Raises:
            AuthRequiredException: If the client is not authenticated.
            FrankEnergieException: If the request fails.
        """
        if not site_reference:
            raise FrankEnergieException("A valid site_reference must be provided.")

        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            query MonthSummary($siteReference: String!) {
                monthSummary(siteReference: $siteReference) {
                    _id
                    actualCostsUntilLastMeterReadingDate
                    expectedCostsUntilLastMeterReadingDate
                    expectedCosts
                    lastMeterReadingDate
                    meterReadingDayCompleteness
                    gasExcluded
                    __typename
                }
                version
                __typename
            }
            """,
            "MonthSummary",
            {"siteReference": site_reference},
        )

        try:
            response = await self._query(query)
            _LOGGER.debug("MonthSummary raw response: %s", response)
            return MonthSummary.from_dict(response)
        except (AuthException, AuthRequiredException):
            raise
        except Exception as e:
            _LOGGER.exception(
                "Month summary failed (%s)",
                type(e).__name__,
            )
            raise FrankEnergieException(f"Failed to fetch month summary: {e}") from e

    async def month_insights(self, site_reference: str, date: str) -> MonthInsights:
        """Retrieve the month insights for the specified month.

        Args:
            month: The month for which to retrieve the insights. Defaults to the current month.

        Returns:
            The month insights information.

        Raises:
            AuthRequiredException: If the client is not authenticated.
            FrankEnergieException: If the request fails.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not isinstance(site_reference, str) or not site_reference.strip():
            raise FrankEnergieException("A valid non-empty site_reference must be provided.")

        if not isinstance(date, str) or not date.strip():
            raise FrankEnergieException("date must be a non-empty string in 'YYYY-MM' format.")

        #        # YYYY-MM validation (strict, zero-padded, 4-digit year)
        #        try:
        #            # datetime.strptime ensures exact format correctness
        #            _ = datetime.strptime(start_date, "%Y-%m")
        #        except ValueError as exc:
        #            raise FrankEnergieException(
        #                "start_date must follow the 'YYYY-MM' format, for example '2025-03'."
        #            ) from exc

        query = FrankEnergieQuery(
            """
            query MonthInsights($date: String!, $siteReference: String!) {
                monthInsights(date: $date, siteReference: $siteReference) {
                    _id
                    expectedCosts
                    expectedCostsGas
                    expectedCostsFixed
                    expectedCostsElectricity
                    expectedCostsFeedIn
                    expectedCostsUntilLastMeterReading
                    actualCostsUntilLastMeterReading
                    lastMeterReadingDate
                    invoiceId
                    gasDifference {
                        actualUsage
                        actualAverageUnitPrice
                        actualCosts
                        expectedUsage
                        expectedAverageUnitPrice
                        expectedCosts
                        unit
                    }
                    electricityDifference {
                        actualUsage
                        actualAverageUnitPrice
                        actualCosts
                        expectedUsage
                        expectedAverageUnitPrice
                        expectedCosts
                        unit
                    }
                    feedInDifference {
                        actualUsage
                        actualAverageUnitPrice
                        actualCosts
                        expectedUsage
                        expectedAverageUnitPrice
                        expectedCosts
                        unit
                    }
                    meterReadingDayCompleteness
                    gasExcluded
                }
            }
            """,
            "MonthInsights",
            {"siteReference": site_reference, "date": str(date)},
        )
        try:
            response_dict = await self._query(query)
        except Exception as exc:
            raise FrankEnergieException(f"Failed to fetch MonthInsights: {exc}") from exc

        try:
            return MonthInsights.from_dict(response_dict)
        except Exception as exc:
            raise FrankEnergieException(f"Failed to parse MonthInsights response: {exc}") from exc

    async def enode_chargers(self, site_reference: str, start_date: date) -> dict[str, EnodeChargers]:
        """Retrieve the enode charger information for the specified site reference.

        Args:
            site_reference: The site reference for which to retrieve the enode charger information.
            start_date: The start date for filtering the enode charger information.

        Returns:
            The enode charger information, or an empty dict if not authenticated.

        Raises:
            FrankEnergieException: If the request fails.
        """
        if not self.is_authenticated:
            return {}

        if not isinstance(site_reference, str) or not site_reference.strip():
            raise FrankEnergieException("A valid non-empty site_reference must be provided.")

        query = FrankEnergieQuery(
            """
            query EnodeChargers {
                enodeChargers {
                    canSmartCharge
                    chargeSettings {
                        calculatedDeadline
                        capacity
                        deadline
                        hourFriday
                        hourMonday
                        hourSaturday
                        hourSunday
                        hourThursday
                        hourTuesday
                        hourWednesday
                        id
                        initialCharge
                        initialChargeTimestamp
                        isSmartChargingEnabled
                        isSolarChargingEnabled
                        maxChargeLimit
                        minChargeLimit
                    }
                    chargeState {
                        batteryCapacity
                        batteryLevel
                        chargeLimit
                        chargeRate
                        chargeTimeRemaining
                        isCharging
                        isFullyCharged
                        isPluggedIn
                        lastUpdated
                        powerDeliveryState
                        range
                    }
                    id
                    information {
                        brand
                        model
                        year
                    }
                    interventions {
                        description
                        title
                    }
                    isReachable
                    lastSeen
                }
            }
            """,
            "EnodeChargers",
            {"siteReference": site_reference},
        )

        try:
            # response = await self._query(query)
            response: dict[str, Any] = await self._query(query)
            # Response data for testing purposes
            # mock_response = {'data': {'enodeChargers': [{'canSmartCharge': True, 'chargeSettings': {'calculatedDeadline': '2025-03-24T06:00:00.000Z', 'capacity': 75, 'deadline': None, 'hourFriday': 420, 'hourMonday': 420, 'hourSaturday': 420, 'hourSunday': 420, 'hourThursday': 420, 'hourTuesday': 420, 'hourWednesday': 420, 'id': 'cm3rogazq06pz13p8eucfutnx', 'initialCharge': 0, 'initialChargeTimestamp': '2024-11-21T19:00:15.396Z', 'isSmartChargingEnabled': True, 'isSolarChargingEnabled': False, 'maxChargeLimit': 80, 'minChargeLimit': 20}, 'chargeState': {'batteryCapacity': None, 'batteryLevel': None, 'chargeLimit': None, 'chargeRate': None, 'chargeTimeRemaining': None, 'isCharging': False, 'isFullyCharged': None, 'isPluggedIn': False, 'lastUpdated': '2025-03-23T16:06:57.000Z', 'powerDeliveryState': 'UNPLUGGED', 'range': None}, 'id': 'cm3rogazq06pz13p8eucfutnx', 'information': {'brand': 'Wallbox', 'model': 'Pulsar Plus 1', 'year': None}, 'interventions': [], 'isReachable': True, 'lastSeen': '2025-03-23T16:24:51.913Z'}, {'canSmartCharge': True, 'chargeSettings': {'calculatedDeadline': '2025-03-24T06:00:00.000Z', 'capacity': 100, 'deadline': None, 'hourFriday': 420, 'hourMonday': 420, 'hourSaturday': 420, 'hourSunday': 420, 'hourThursday': 420, 'hourTuesday': 420, 'hourWednesday': 420, 'id': 'cm3rogap606pu13p8w08epzjx', 'initialCharge': 0, 'initialChargeTimestamp': '2024-11-21T19:00:15.016Z', 'isSmartChargingEnabled': True, 'isSolarChargingEnabled': False, 'maxChargeLimit': 80, 'minChargeLimit': 20}, 'chargeState': {'batteryCapacity': None, 'batteryLevel': None, 'chargeLimit': None, 'chargeRate': 10.71, 'chargeTimeRemaining': None, 'isCharging': True, 'isFullyCharged': None, 'isPluggedIn': True, 'lastUpdated': '2025-03-23T16:23:53.000Z', 'powerDeliveryState': 'PLUGGED_IN:CHARGING', 'range': None}, 'id': 'cm3rogap606pu13p8w08epzjx', 'information': {'brand': 'Wallbox', 'model': 'Pulsar Plus 2', 'year': None}, 'interventions': [], 'isReachable': True, 'lastSeen': '2025-03-23T16:24:50.746Z'}]}}
            if response is None:
                _LOGGER.debug("No response data for 'enodeChargers'")
                return {}
            if "data" not in response:
                _LOGGER.debug("No data found in response for chargers: %s", response)
                return {}
            if response["data"] is None:
                _LOGGER.debug("No data for chargers found: %s", response)
                return {}
            if "enodeChargers" not in response["data"]:
                _LOGGER.debug("No chargers found in data: %s", response)
                return {}
            chargers_data = response.get("data", {}).get("enodeChargers", [])
            _LOGGER.info("%s Enode Chargers Found", len(chargers_data))
            _LOGGER.debug("Enode Chargers data: %s", chargers_data)
            # _LOGGER.debug("Format for 'enodeChargers' response: %s", type(response))
            # _LOGGER.debug("Format for 'enodeChargers' chargers: %s", type(chargers))
            # response is a disctionary, but the data is a list of dictionaries
            # chargers is a list of dictionaries, but the data is a dictionary
            # if not isinstance(chargers, list):
            #     _LOGGER.debug("Unexpected format for 'enodeChargers': %s", chargers)
            #     return []
            return EnodeChargers.from_dict(chargers_data)
        except SmartChargingNotEnabledException as error:
            _LOGGER.debug("Smart charging not enabled: %s", error)
            return {}
        except Exception as error:
            _LOGGER.debug("Error in enode_chargers: %s", error)
            _LOGGER.exception("Unexpected error during query: %s", error)
            return {}
            # raise FrankEnergieException("Unexpected error occurred.") from error

    #        except Exception as e:
    #            raise FrankEnergieException(
    #              f"Failed to fetch Enode Chargers: {e}"
    #              ) from e

    async def invoices(self, site_reference: str) -> Invoices:
        """Retrieve the invoices data.

        Returns an Invoices object containing all, previous, current,
        and upcoming invoices.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not isinstance(site_reference, str) or not site_reference.strip():
            raise ValueError("A valid non-empty site_reference must be provided.")

        query = FrankEnergieQuery(
            """
            query Invoices($siteReference: String!) {
                invoices(siteReference: $siteReference) {
                    allInvoices {
                        id
                        invoiceDate
                        startDate
                        periodDescription
                        totalAmount
                        __typename
                    }
                    previousPeriodInvoice {
                        id
                        startDate
                        periodDescription
                        totalAmount
                        __typename
                    }
                    currentPeriodInvoice {
                        id
                        startDate
                        periodDescription
                        totalAmount
                        __typename
                    }
                    upcomingPeriodInvoice {
                        id
                        startDate
                        periodDescription
                        totalAmount
                        __typename
                    }
                __typename
                }
            __typename
            }
            """,
            "Invoices",
            {"siteReference": site_reference},
        )

        response = await self._query(query)
        return Invoices.from_dict(response)

    async def disable_smart_trading(self) -> bool:
        """Disable smart trading for the authenticated user.

        Calls the ``DisableSmartTrading`` GraphQL mutation.

        Returns:
            True if the API reported success, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation DisableSmartTrading {
              disableSmartTrading {
                success
              }
            }
            """,
            "DisableSmartTrading",
        )

        try:
            _LOGGER.debug("Disabling smart trading")
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to disable smart trading")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when disabling smart trading: %s", response)
            return False

        return bool(response.get("data", {}).get("disableSmartTrading", {}).get("success", False))

    async def disable_smart_feed_in(self) -> bool:
        """Disable smart feed-in for the authenticated user.

        Calls the ``SmartFeedInDisable`` GraphQL mutation.

        Returns:
            True if the API reported success, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation SmartFeedInDisable {
              smartFeedInDisable {
                success
              }
            }
            """,
            "SmartFeedInDisable",
        )

        try:
            _LOGGER.debug("Disabling smart feed-in")
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to disable smart feed-in")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when disabling smart feed-in: %s", response)
            return False

        return bool(response.get("data", {}).get("smartFeedInDisable", {}).get("success", False))

    async def enode_update_vehicle_charge_settings(self, input_data: dict[str, Any]) -> bool:
        """Update the charge settings for a specific Enode vehicle.

        Calls the ``EnodeUpdateVehicleChargeSettings`` GraphQL mutation.
        The ``input_data`` dict must include the charge settings ``id`` and any
        fields to update (e.g. ``deadline``, ``isSmartChargingEnabled``,
        ``minChargeLimit``, ``maxChargeLimit``, ``hourMonday`` … ``hourSunday``).

        Args:
            input_data: A dict matching ``EnodeUpdateVehicleChargeSettingsInputType``.
                Required key: ``id`` (the ChargeSettings.id from the vehicle).

        Returns:
            True if the mutation was accepted without errors, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
            ValueError: If ``input_data`` is missing the required ``id`` field.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if "id" not in input_data:
            raise ValueError("input_data must include the charge settings 'id' field.")

        query = FrankEnergieQuery(
            """
            mutation EnodeUpdateVehicleChargeSettings($input: EnodeUpdateVehicleChargeSettingsInputType!) {
              enodeUpdateVehicleChargeSettings(input: $input)
            }
            """,
            "EnodeUpdateVehicleChargeSettings",
            {"input": input_data},
        )

        try:
            _LOGGER.debug("Updating vehicle charge settings for id=%s", input_data.get("id"))
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to update vehicle charge settings")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when updating vehicle charge settings: %s", response)
            return False

        return True

    async def enode_update_charger_charge_settings(self, input_data: dict[str, Any]) -> bool:
        """Update the charge settings for a specific Enode wall charger.

        Calls the ``EnodeUpdateChargerChargeSettings`` GraphQL mutation.
        The ``input_data`` dict must include the charge settings ``id`` and any
        fields to update (e.g. ``deadline``, ``isSmartChargingEnabled``,
        ``capacity``, ``initialCharge``, ``hourMonday`` … ``hourSunday``).

        Args:
            input_data: A dict matching ``EnodeUpdateChargerChargeSettingsInputType``.
                Required key: ``id`` (the ChargeSettings.id from the charger).

        Returns:
            True if the mutation was accepted without errors, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
            ValueError: If ``input_data`` is missing the required ``id`` field.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if "id" not in input_data:
            raise ValueError("input_data must include the charge settings 'id' field.")

        query = FrankEnergieQuery(
            """
            mutation EnodeUpdateChargerChargeSettings($input: EnodeUpdateChargerChargeSettingsInputType!) {
              enodeUpdateChargerChargeSettings(input: $input)
            }
            """,
            "EnodeUpdateChargerChargeSettings",
            {"input": input_data},
        )

        try:
            _LOGGER.debug("Updating charger charge settings for id=%s", input_data.get("id"))
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to update charger charge settings")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when updating charger charge settings: %s", response)
            return False

        return True

    async def enode_enable_smart_charging(self) -> bool:
        """Enable Enode smart charging for the authenticated user.

        Calls the ``EnodeEnableSmartCharging`` GraphQL mutation.

        Returns:
            True if the API returned a userId (indicating success), False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation EnodeEnableSmartCharging {
              enodeEnableSmartCharging {
                userId
              }
            }
            """,
            "EnodeEnableSmartCharging",
        )

        try:
            _LOGGER.debug("Enabling Enode smart charging")
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to enable Enode smart charging")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when enabling Enode smart charging: %s", response)
            return False

        return bool(response.get("data", {}).get("enodeEnableSmartCharging", {}).get("userId"))

    async def enode_disable_smart_charging(self) -> bool:
        """Disable Enode smart charging for the authenticated user.

        Calls the ``EnodeDisableSmartCharging`` GraphQL mutation.

        Returns:
            True if the mutation was accepted without errors and returned True, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation EnodeDisableSmartCharging {
              enodeDisableSmartCharging
            }
            """,
            "EnodeDisableSmartCharging",
        )

        try:
            _LOGGER.debug("Disabling Enode smart charging")
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to disable Enode smart charging")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when disabling Enode smart charging: %s", response)
            return False

        return bool(response.get("data", {}).get("enodeDisableSmartCharging", False))

    async def disable_smart_hvac(self) -> bool:
        """Disable smart HVAC for the authenticated user.

        Calls the ``SmartHvacDisable`` GraphQL mutation.

        Returns:
            True if the API reported success, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation SmartHvacDisable {
              smartHvacDisable {
                success
              }
            }
            """,
            "SmartHvacDisable",
        )

        try:
            _LOGGER.debug("Disabling smart HVAC")
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to disable smart HVAC")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when disabling smart HVAC: %s", response)
            return False

        return bool(response.get("data", {}).get("smartHvacDisable", {}).get("success", False))

    async def smart_hvac_update_settings(self, device_id: str, settings: dict[str, Any]) -> bool:
        """Update settings for a smart HVAC device.

        Calls the ``SmartHvacUpdateSettings`` GraphQL mutation.
        Writable fields via ``SmartHvacUpdateSettingsInput``:
        ``mode``, ``temperatureLowerBound``, ``temperatureUpperBound``.

        Args:
            device_id: The HVAC device ID.
            settings: A dict matching ``SmartHvacUpdateSettingsInput``.
                Example: ``{"mode": "SMART", "temperatureLowerBound": 18.0,
                "temperatureUpperBound": 22.0}``

        Returns:
            True if the mutation was accepted without errors, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation SmartHvacUpdateSettings($deviceId: String!, $settings: SmartHvacUpdateSettingsInput!) {
              smartHvacUpdateSettings(deviceId: $deviceId, settings: $settings) {
                createdAt
                mode
                temperatureLowerBound
                temperatureUpperBound
                updatedAt
              }
            }
            """,
            "SmartHvacUpdateSettings",
            {"deviceId": device_id, "settings": settings},
        )

        try:
            _LOGGER.debug("Updating smart HVAC settings for device %s", device_id)
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to update smart HVAC settings for device %s", device_id)
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when updating HVAC settings: %s", response)
            return False

        return True

    # -------------------------------------------------------------------------
    # Smart controls — API stubs for future use (not yet used by HA)
    # -------------------------------------------------------------------------

    async def smart_battery_update_settings(self, device_id: str, settings: dict[str, Any]) -> bool:
        """Update settings for a smart battery device.

        Calls the ``SmartBatteryUpdateSettings`` GraphQL mutation.
        Writable fields via ``SmartBatteryUpdateSettingsInput``:
        ``batteryMode``, ``imbalanceTradingStrategy``,
        ``selfConsumptionTradingThresholdPrice``.

        Note:
            ``selfConsumptionTradingAllowed`` is a read-only status field and
            cannot be set via this mutation.

        Args:
            device_id: The battery device ID.
            settings: A dict matching ``SmartBatteryUpdateSettingsInput``.

        Returns:
            True if the mutation was accepted without errors, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation SmartBatteryUpdateSettings($deviceId: String!, $settings: SmartBatteryUpdateSettingsInput!) {
              smartBatteryUpdateSettings(deviceId: $deviceId, settings: $settings) {
                batteryMode
                createdAt
                imbalanceTradingStrategy
                selfConsumptionTradingThresholdPrice
                updatedAt
              }
            }
            """,
            "SmartBatteryUpdateSettings",
            {"deviceId": device_id, "settings": settings},
        )

        try:
            _LOGGER.debug("Updating smart battery settings for device %s", device_id)
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to update smart battery settings for device %s", device_id)
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when updating battery settings: %s", response)
            return False

        return True

    async def enode_update_all_vehicle_charge_settings(self, input_data: dict[str, Any]) -> bool:
        """Bulk-update charge settings for all Enode vehicles.

        Calls the ``EnodeUpdateAllVehicleChargeSettings`` GraphQL mutation.
        Use this to apply the same deadline or charge limits to every vehicle
        at once.

        Args:
            input_data: A dict matching ``EnodeUpdateAllVehicleChargeSettingsInputType``.

        Returns:
            True if the mutation was accepted without errors, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation EnodeUpdateAllVehicleChargeSettings($input: EnodeUpdateAllVehicleChargeSettingsInputType!) {
              enodeUpdateAllVehicleChargeSettings(input: $input)
            }
            """,
            "EnodeUpdateAllVehicleChargeSettings",
            {"input": input_data},
        )

        try:
            _LOGGER.debug("Bulk-updating all vehicle charge settings")
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to bulk-update vehicle charge settings")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when bulk-updating vehicle charge settings: %s", response)
            return False

        return True

    async def logout(self, installation_id: str) -> bool:
        """Log out and invalidate the current session.

        Calls the ``Logout`` GraphQL mutation.

        Args:
            installation_id: The installation ID of the device to log out.

        Returns:
            True if the mutation was accepted without errors and returned True, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation Logout($installationId: String!) {
              logout(installationId: $installationId)
            }
            """,
            "Logout",
            {"installationId": installation_id},
        )

        try:
            _LOGGER.debug("Logging out installation %s", installation_id)
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to log out installation %s", installation_id)
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when logging out: %s", response)
            return False

        ok = bool(response.get("data", {}).get("logout", False))
        if ok:
            self._auth = None
        return ok

    async def update_user_settings(self, input_data: dict[str, Any]) -> bool:
        """Update user-level app settings.

        Calls the ``UpdateUserSettings`` GraphQL mutation.
        Writable fields via ``UpdateUserSettingsInput``:
        ``disabledHapticFeedback``, ``language``, ``rewardPayoutPreference``,
        ``smartPushNotifications``.

        Args:
            input_data: A dict matching ``UpdateUserSettingsInput``.

        Returns:
            True if the mutation was accepted without errors, False otherwise.

        Raises:
            AuthRequiredException: If the client is not authenticated.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            mutation UpdateUserSettings($input: UpdateUserSettingsInput!) {
              updateUserSettings(input: $input) {
                id
                UserSettings {
                  id
                  disabledHapticFeedback
                  language
                  rewardPayoutPreference
                  smartPushNotifications
                }
              }
            }
            """,
            "UpdateUserSettings",
            {"input": input_data},
        )

        try:
            _LOGGER.debug("Updating user settings")
            response = await self._query(query)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to update user settings")
            return False

        if not response or response.get("errors"):
            _LOGGER.warning("Error response when updating user settings: %s", response)
            return False

        return True

    async def old_me(self, site_reference: str) -> Me:
        """Fetch authenticated user data."""

        if self._auth is None:
            raise AuthRequiredException("Authentication is required.")

        if site_reference is None or not isinstance(site_reference, str) or not site_reference.strip():
            raise ValueError("A valid non-empty site_reference must be provided.")

        query = FrankEnergieQuery(
            """
            query Me($siteReference: String) {
                me {
                    ...UserFields
                }
            }
            fragment UserFields on User {
                id
                email
                countryCode
                advancedPaymentAmount(siteReference: $siteReference)
                treesCount
                hasInviteLink
                hasCO2Compensation
                createdAt
                updatedAt
                meterReadingExportPeriods(siteReference: $siteReference) {
                    EAN
                    cluster
                    segment
                    from
                    till
                    period
                    type
                }
                InviteLinkUser {
                    id
                    fromName
                    slug
                    treesAmountPerConnection
                    discountPerConnection
                }
                PushNotificationPriceAlerts {
                    id
                    isEnabled
                    type
                    weekdays
                }
                UserSettings {
                    id
                    disabledHapticFeedback
                    language
                    smartPushNotifications
                    rewardPayoutPreference
                }
                activePaymentAuthorization {
                    id
                    mandateId
                    signedAt
                    bankAccountNumber
                    status
                }
                connections(siteReference: $siteReference) {
                    id
                    connectionId
                    EAN
                    segment
                    status
                    contractStatus
                    estimatedFeedIn
                    firstMeterReadingDate
                    lastMeterReadingDate
                    meterType
                    externalDetails {
                        gridOperator
                        address {
                            street
                            houseNumber
                            houseNumberAddition
                            zipCode
                            city
                        }
                        contract {
                            startDate
                            endDate
                            contractType
                            productName
                            tariffChartId
                        }
                    }
                }
                externalDetails {
                    reference
                    person {
                        firstName
                        lastName
                    }
                    contact {
                        emailAddress
                        phoneNumber
                        mobileNumber
                    }
                    address {
                        addressFormatted
                        street
                        houseNumber
                        houseNumberAddition
                        zipCode
                        city
                    }
                    debtor {
                        bankAccountNumber
                        preferredAutomaticCollectionDay
                    }
                }
                smartCharging {
                    isActivated
                    provider
                    userCreatedAt
                    userId
                    isAvailableInCountry
                    needsSubscription
                    subscription {
                        startDate
                        endDate
                        id
                        proposition {
                            product
                            countryCode
                        }
                    }
                }
                smartTrading {
                    isActivated
                    isAvailableInCountry
                    userCreatedAt
                    userId
                }
                websiteUrl
                customerSupportEmail
                reference
            }
            """,
            "Me",
            {"siteReference": site_reference},
        )

        response = await self._query(query)

        if not isinstance(response, dict):
            raise RequestException("Invalid response type for 'me' query")

        return Me.from_dict(response)

    async def me(self, site_reference: str | None = None) -> Me:
        """Fetch authenticated user data."""

        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not site_reference or not isinstance(site_reference, str) or not site_reference.strip():
            raise ValueError("A valid non-empty site_reference must be provided.")

        query = FrankEnergieQuery(
            """
            query Me($siteReference: String!) {
                me {
                    ...UserCore
                    ...UserFields
                    ...UserFinancial
                    ...UserMetering
                    ...UserConnections
                    ...UserExternalDetails
                    ...UserSmartFeatures
                    ...UserMisc
                }
            }
            fragment UserCore on User {
                id
                email
                countryCode
                createdAt
                updatedAt
            }
            fragment UserFinancial on User {
                advancedPaymentAmount(siteReference: $siteReference)
                treesCount
                hasInviteLink
                hasCO2Compensation
            }
            fragment UserMetering on User {
                meterReadingExportPeriods(siteReference: $siteReference) {
                    EAN
                    cluster
                    segment
                    from
                    till
                    period
                    type
                }
            }
            fragment UserConnections on User {
                connections(siteReference: $siteReference) {
                    id
                    connectionId
                    EAN
                    segment
                    status
                    contractStatus
                    estimatedFeedIn
                    firstMeterReadingDate
                    lastMeterReadingDate
                    meterType
                    externalDetails {
                        gridOperator
                        address {
                            street
                            houseNumber
                            houseNumberAddition
                            zipCode
                            city
                        }
                        contract {
                            startDate
                            endDate
                            contractType
                            productName
                            tariffChartId
                        }
                    }
                }
            }
            fragment UserFields on User {
                InviteLinkUser {
                    id
                    fromName
                    slug
                    treesAmountPerConnection
                    discountPerConnection
                }
                PushNotificationPriceAlerts {
                    id
                    isEnabled
                    type
                    weekdays
                }
                UserSettings {
                    id
                    disabledHapticFeedback
                    language
                    smartPushNotifications
                    rewardPayoutPreference
                }
                activePaymentAuthorization {
                    id
                    mandateId
                    signedAt
                    bankAccountNumber
                    status
                }
            }
            fragment UserExternalDetails on User {
                externalDetails {
                    reference
                    person {
                        firstName
                        lastName
                    }
                    contact {
                        emailAddress
                        phoneNumber
                        mobileNumber
                    }
                    address {
                        addressFormatted
                        street
                        houseNumber
                        houseNumberAddition
                        zipCode
                        city
                    }
                    debtor {
                        bankAccountNumber
                        preferredAutomaticCollectionDay
                    }
                }
            }
            fragment UserSmartFeatures on User {
                smartCharging {
                    isActivated
                    provider
                    userCreatedAt
                    userId
                    isAvailableInCountry
                    needsSubscription
                    subscription {
                        startDate
                        endDate
                        id
                        proposition {
                            product
                            countryCode
                        }
                    }
                }
                smartTrading {
                    isActivated
                    isAvailableInCountry
                    userCreatedAt
                    userId
                }
            }
            fragment UserMisc on User {
                websiteUrl
                customerSupportEmail
                reference
            }
            """,
            "Me",
            {"siteReference": site_reference},
        )

        response = await self._query(query)

        # Minimal safeguard (optional but useful for debugging contract breaks)
        if not isinstance(response, dict):
            raise RequestException("Invalid response type for 'me' query")

        return Me.from_dict(response)

    async def UserSites(self, site_reference: str | None = None) -> UserSites:
        if self._auth is None:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            query UserSites {
                userSites {
                    address {
                        addressFormatted
                    }
                    addressHasMultipleSites
                    deliveryEndDate
                    deliveryStartDate
                    firstMeterReadingDate
                    lastMeterReadingDate
                    propositionType
                    reference
                    segments
                    status
                }
            }
            """,
            "UserSites",
            {},
        )

        response = await self._query(query)

        if not isinstance(response, dict):
            raise RequestException("Invalid response type for 'UserSites' query")

        return UserSites.from_dict(response)

    async def contract_price_resolution_state(
        self,
        connection_id: str | None = None,
    ) -> ContractPriceResolutionState | None:
        """
        Fetch the contract price resolution state for a given connection.

        Args:
            connection_id: The ID of the connection to query.

        Raises:
            AuthRequiredException: If authentication has not been performed.
            ValueError: If connection_id is None.

        Returns:
            ContractPriceResolutionState | None:
                The contract price resolution state, or None if the
                response is invalid or cannot be parsed.
        """
        if self._auth is None:
            raise AuthRequiredException("Authentication is required.")

        if connection_id is None:
            raise ValueError("connection_id must be provided")

        query = FrankEnergieQuery(
            """
            query ContractPriceResolutionState($connectionId: String!) {
                contractPriceResolutionState(connectionId: $connectionId) {
                    activeOption
                    availableOptions
                    changeRequestEffectiveDate
                    isChangeRequestPossible
                    upcomingChange
                    upcomingChangeEffectiveDate
                }
            }
            """,
            "ContractPriceResolutionState",
            {"connectionId": connection_id},
        )

        try:
            _LOGGER.debug("Fetching contract price resolution state for connection ID: %s", connection_id)
            response = await self._query(query)

            if not isinstance(response, dict):
                _LOGGER.error(
                    "Unexpected response type for contractPriceResolutionState: %r",
                    response,
                )
                return None

            response_data = response.get("data")
            if not isinstance(response_data, dict):
                _LOGGER.error(
                    "Unexpected response data structure for contractPriceResolutionState: %s",
                    response,
                )
                return None

            data = response_data.get("contractPriceResolutionState")
            if not isinstance(data, dict):
                _LOGGER.error(
                    "Unexpected contractPriceResolutionState structure: %s",
                    response_data,
                )
                return None

            return ContractPriceResolutionState.from_dict(data)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to fetch contract price resolution state")
            return None

    async def contract_price_resolution_request_change(
        self,
        connection_id: str | None = None,
        resolution: Resolution | None = None,
    ) -> ContractPriceResolutionChangeResult | None:
        """Request a change to the contract price resolution."""
        if self._auth is None:
            raise AuthRequiredException("Authentication is required.")

        if not isinstance(connection_id, str) or not connection_id.strip():
            raise ValueError("connection_id must be provided and be a non-empty string")

        if resolution is None:
            raise ValueError("resolution must be provided")

        try:
            resolution_enum = Resolution(resolution)
        except ValueError as e:
            raise ValueError(
                f"resolution must be a valid Resolution enum or one of: {[r.value for r in Resolution]}"
            ) from e

        query = FrankEnergieQuery(
            """
            mutation ContractPriceResolutionRequestChange($connectionId: String!, $resolution: PriceResolution!) {
            contractPriceResolutionRequestChange(
                connectionId: $connectionId
                resolution: $resolution
            ) {
                data {
                effectiveDate
                }
                reason
                success
            }
            }
            """,
            "ContractPriceResolutionRequestChange",
            {
                "connectionId": connection_id,
                "resolution": resolution_enum.value,
            },
        )

        try:
            _LOGGER.debug(
                "Requesting contract price resolution change for connection ID %s to %s",
                connection_id,
                resolution_enum.value,
            )

            response = await self._query(query)

            return self._parse_contract_price_resolution_change_response(
                response,
            )

        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Failed to request contract price resolution change")
            return None

    def _parse_contract_price_resolution_change_response(
        self,
        response: dict[str, object] | None,
    ) -> ContractPriceResolutionChangeResult | None:
        """Parse a contract price resolution change response."""
        if not isinstance(response, dict):
            _LOGGER.error(
                "Unexpected response type for contractPriceResolutionRequestChange: %r",
                response,
            )
            return None

        response_data = response.get("data")

        if not isinstance(response_data, dict):
            _LOGGER.error(
                "Unexpected response data structure for contractPriceResolutionRequestChange: %s",
                response,
            )
            return None

        result = response_data.get("contractPriceResolutionRequestChange")

        if not isinstance(result, dict):
            _LOGGER.error(
                "Unexpected contractPriceResolutionRequestChange structure: %s",
                response_data,
            )
            return None

        return ContractPriceResolutionChangeResult.from_dict(result)

    # query UserCountry {\\n  me {\\n    countryCode\\n  }\\n}\\n\",\"operationName\":\"UserCountry\"}
    # query UserSmartCharging {\\n  userSmartCharging {\\n    isActivated\\n    provider\\n    userCreatedAt\\n    userId\\n    isAvailableInCountry\\n    needsSubscription\\n    subscription {\\n      startDate\\n      endDate\\n      id\\n      proposition {\\n        product\\n        countryCode\\n      }\\n    }\\n  }\\n}\\n\",\"operationName\":\"UserSmartCharging\"}
    # {\"query\":\"query AppVersion {\\n  appVersion {\\n    ios {\\n      version\\n    }\\n    android {\\n      version\\n    }\\n  }\\n}\\n\",\"operationName\":\"AppVersion\"}"
    # \"query UserRewardsData {\\n  me {\\n    id\\n    UserSettings {\\n      id\\n      rewardPayoutPreference\\n    }\\n  }\\n  userRewardsData {\\n    activeConnectionsCount\\n    activeFriendsCount\\n    acceptedRewards {\\n      ...UserRewardV2Fields\\n    }\\n    upcomingRewards {\\n      ...UserRewardV2Fields\\n    }\\n  }\\n}\\n\\nfragment UserRewardV2Fields on UserRewardV2 {\\n  id\\n  awardedDiscount\\n  awardedTreesAmount\\n  availableForAcceptanceOn\\n  treesAmountPerConnection\\n  discountPerConnection\\n  acceptedOn\\n  isRewardForOwnSignup\\n  hasPossibleSmartChargingBonus\\n  coolingDownPeriod\\n  InviteLink {\\n    id\\n    type\\n    fromName\\n    templateType\\n    awardRewardType\\n    treesAmountPerConnection\\n    discountPerConnection\\n  }\\n  AdditionalBonuses {\\n    discountAmountPerConnection\\n    treesAmountPerConnection\\n    type\\n  }\\n}\\n\",\"operationName\":\"UserRewardsData\"}"
    # \"query TreeCertificates {\\n  treeCertificates {\\n    id\\n    imageUrl\\n    imagePath\\n    createdAt\\n    treesAmount\\n  }\\n}\\n\",\"operationName\":\"TreeCertificates\"}"
    # \"query AppNotice {\\n  appNotice {\\n    active\\n    message\\n    title\\n  }\\n}\\n\",\"operationName\":\"AppNotice\"}"

    async def user_country(self) -> Me:
        """Fetch a minimal Me payload containing authenticated user countryCode."""

        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            query UserCountry {
                me {
                    countryCode
                    }
            }
            """,
            "UserCountry",
            {},
        )

        response = await self._query(query)
        return Me.from_dict(response)

    async def user(self, site_reference: str | None = None) -> User:
        """Fetch authenticated user data."""
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if site_reference is None or not isinstance(site_reference, str) or not site_reference.strip():
            raise ValueError("A valid non-empty site_reference must be provided.")

        query = FrankEnergieQuery(
            """
            query Me($siteReference: String) {
                me {
                    ...UserFields
                }
            }
            fragment UserFields on User {
                id
                email
                countryCode
                advancedPaymentAmount(siteReference: $siteReference)
                treesCount
                hasInviteLink
                hasCO2Compensation
                createdAt
                updatedAt
                meterReadingExportPeriods(siteReference: $siteReference) {
                    EAN
                    cluster
                    segment
                    from
                    till
                    period
                    type
                }
                InviteLinkUser {
                    id
                    fromName
                    slug
                    treesAmountPerConnection
                    discountPerConnection
                }
                UserSettings {
                    id
                    disabledHapticFeedback
                    language
                    smartPushNotifications
                    rewardPayoutPreference
                }
                activePaymentAuthorization {
                    id
                    mandateId
                    signedAt
                    bankAccountNumber
                    status
                }
                meterReadingExportPeriods(siteReference: $siteReference) {
                    EAN
                    cluster
                    segment
                    from
                    till
                    period
                    type
                }
                connections(siteReference: $siteReference) {
                    id
                    connectionId
                    EAN
                    segment
                    status
                    contractStatus
                    estimatedFeedIn
                    firstMeterReadingDate
                    lastMeterReadingDate
                    meterType
                    externalDetails {
                        gridOperator
                        address {
                            street
                            houseNumber
                            houseNumberAddition
                            zipCode
                            city
                        }
                        contract {
                            startDate
                            endDate
                            contractType
                            productName
                            tariffChartId
                        }
                    }
                }
                externalDetails {
                    reference
                    person {
                        firstName
                        lastName
                    }
                    contact {
                        emailAddress
                        phoneNumber
                        mobileNumber
                    }
                    address {
                        street
                        houseNumber
                        houseNumberAddition
                        zipCode
                        city
                    }
                    debtor {
                        bankAccountNumber
                        preferredAutomaticCollectionDay
                    }
                }
                smartCharging {
                    isActivated
                    provider
                    userCreatedAt
                    userId
                    isAvailableInCountry
                    needsSubscription
                    subscription {
                        startDate
                        endDate
                        id
                        proposition {
                            product
                            countryCode
                        }
                    }
                }
                smartTrading {
                    isActivated
                    isAvailableInCountry
                    userCreatedAt
                    userId
                }
                websiteUrl
                customerSupportEmail
                reference
            }
            """,
            "Me",
            {"siteReference": site_reference},
        )

        response = await self._query(query)
        user = User.from_dict(response)
        if user is None:
            raise FrankEnergieException("Failed to parse authenticated user data")
        return user

    async def smart_hvac_status(self) -> SmartHvac | None:
        """Fetch smart HVAC status."""
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            query SmartHvacStatus {
                me {
                    smartHvac {
                        isActivated
                        isAvailableInCountry
                        userCreatedAt
                        userId
                    }
                }
            }
            """,
            "SmartHvacStatus",
        )
        response = await self._query(query)
        if not isinstance(response, dict):
            raise RequestException("Invalid response type for 'smart_hvac_status' query")
        raw = response.get("data", {}).get("me", {}).get("smartHvac")
        return SmartHvac.from_dict(raw)

    async def be_prices(self, start_date: date | None = None, end_date: date | None = None) -> MarketPrices:
        """Get belgium market prices."""
        if start_date is None:
            start_date = datetime.now(UTC).date()
        if end_date is None:
            end_date = start_date + timedelta(days=1)

        headers = {"x-country": "BE"}

        query = FrankEnergieQuery(
            """
            query MarketPrices ($date: String!) {
                marketPrices(date: $date) {
                    electricityPrices {
                        from
                        till
                        resolution
                        marketPrice
                        marketPriceTax
                        sourcingMarkupPrice
                        energyTaxPrice
                        perUnit
                        __typename
                    }
                    gasPrices {
                        from
                        till
                        resolution
                        marketPrice
                        marketPriceTax
                        sourcingMarkupPrice
                        energyTaxPrice
                        perUnit
                        __typename
                    }
                __typename
                }
            }
            """,
            "MarketPrices",
            {"date": str(start_date)},
        )
        response = await self._query(query, extra_headers=headers)
        return MarketPrices.from_be_dict(response)

    async def prices(
        self,
        start_date: date | None | None = None,
        end_date: date | None | None = None,
        resolution: str | None | None = None,
    ) -> MarketPrices:
        """Get market prices."""
        if not start_date:
            start_date = date.today()

        query = FrankEnergieQuery(
            """
            query MarketPrices($date: String!, $resolution: PriceResolution!) {\n
                marketPrices(date: $date, resolution: $resolution) {\n
                    averageElectricityPrices {\n
                        averageMarketPrice\n
                        averageMarketPricePlus\n
                        averageAllInPrice\n
                        perUnit\n
                        isWeighted\n
                        __typename\n
                    }\n
                    electricityPrices {\n
                        from\n
                        till\n
                        resolution\n
                        marketPrice\n
                        marketPriceTax\n
                        sourcingMarkupPrice\n
                        energyTaxPrice\n
                        marketPricePlus\n
                        allInPrice\n
                        perUnit\n
                        __typename\n
                    }\n
                    gasPrices {\n
                        from\n
                        till\n
                        resolution\n
                        marketPrice\n
                        marketPriceTax\n
                        sourcingMarkupPrice\n
                        energyTaxPrice\n
                        marketPricePlus\n
                        allInPrice\n
                        perUnit\n
                        __typename\n
                    }\n
                __typename\n
                }\n
            }\n
            """,
            "MarketPrices",
            {"date": str(start_date), "resolution": resolution},
        )
        response = await self._query(query)
        return MarketPrices.from_dict(response)

    async def user_prices(
        self,
        site_reference: str,
        user_country: str,
        start_date: date,
        end_date: date | None = None,
        resolution: str | None = "PT15M",
    ) -> MarketPrices:
        """Get customer market prices."""
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not start_date:
            start_date = date.today()
        if not end_date:
            end_date = date.today() + timedelta(days=1)

        query = FrankEnergieQuery(
            """
            query MarketPrices($date: String!, $siteReference: String!) {
                customerMarketPrices(date: $date, siteReference: $siteReference) {
                    id
                    averageElectricityPrices {
                        averageMarketPrice
                        averageMarketPricePlus
                        averageAllInPrice
                        perUnit
                        isWeighted
                        __typename
                    }
                    electricityPrices {
                        id
                        date
                        from
                        till
                        resolution
                        marketPrice
                        marketPricePlus
                        marketPriceTax
                        sourcingMarkupPrice: consumptionSourcingMarkupPrice
                        energyTaxPrice: energyTax
                        allInPrice
                        perUnit
                        __typename
                    }
                    gasPrices {
                        id
                        date
                        from
                        till
                        resolution
                        marketPrice
                        marketPricePlus
                        marketPriceTax
                        sourcingMarkupPrice: consumptionSourcingMarkupPrice
                        energyTaxPrice: energyTax
                        perUnit
                        allInPriceComponents {
                            name
                            value
                            __typename
                        }
                        marketPricePlusComponents {
                            name
                            value
                            __typename
                        }
                        __typename
                    }
                __typename
                }
            }
            """,
            "MarketPrices",
            {"date": str(start_date), "siteReference": str(site_reference)},
        )
        response = await self._query(query)
        return MarketPrices.from_userprices_dict(response, user_country)

    async def period_usage_and_costs(
        self,
        site_reference: str,
        start_date: str,
    ) -> "PeriodUsageAndCosts":
        """
        Haalt het verbruik en de kosten op voor een specifieke periode en locatie.
        Dit is net als op de factuur de marktprijs+

        Args:
            site_reference (str): De referentie van de locatie.
            start_date (str | datetime.date): De startdatum van de periode waarvoor de gegevens moeten worden opgehaald.

        Returns:
            PeriodUsageAndCosts: Het verbruik en de kosten van gas, elektriciteit en teruglevering.

        Raises:
            AuthRequiredException: Als de authenticatie ontbreekt.
            FrankEnergieAPIException: Als de API een fout retourneert.
            ValueError: Als de site_reference leeg is of start_date in de toekomst ligt.
        """

        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not site_reference:
            raise ValueError("De 'site_reference' mag niet leeg zijn.")

        if not start_date:
            raise ValueError("De 'start_date' is vereist.")

        self._validate_start_date_format(start_date)

        query = FrankEnergieQuery(
            """
            query PeriodUsageAndCosts($date: String!, $siteReference: String!) {
                periodUsageAndCosts(date: $date, siteReference: $siteReference) {
                    _id
                    gas{
                        usageTotal
                        costsTotal
                        unit
                        items{
                            date
                            from
                            till
                            usage
                            costs
                            unit
                            __typename
                        }
                        __typename
                    }
                    electricity{
                        usageTotal
                        costsTotal
                        unit
                        items{
                            date
                            from
                            till
                            usage
                            costs
                            unit
                            __typename
                        }
                        __typename
                    }
                    feedIn {
                        usageTotal
                        costsTotal
                        unit
                        items {
                            date
                            from
                            till
                            usage
                            costs
                            unit
                            __typename
                        }
                        __typename
                    }
                    __typename
                }
                __typename
            }
            """,
            "PeriodUsageAndCosts",
            {
                "siteReference": site_reference,
                "date": str(start_date),
            },
        )

        try:
            response = await self._query(query)
            period_usage = PeriodUsageAndCosts.from_dict(response)
            if period_usage is None:
                raise FrankEnergieException("Kon verbruik en kosten niet ophalen voor opgegeven periode.")
            return period_usage
        except Exception as err:
            _LOGGER.exception(
                "Fout bij ophalen van periodUsageAndCosts voor site %s op %s: %s", site_reference, start_date, err
            )
            raise FrankEnergieException("Kon verbruik en kosten niet ophalen voor opgegeven periode.") from err

    # async def smart_batteries(self) -> SmartBatteries: # < better for HA, but less explicit about possible None return
    async def smart_batteries(self) -> SmartBatteries | None:
        """Get the users smart batteries.
        For this to work, the user must have a smart battery connected to their account and smart-trading must be enabled.

        Returns a list of all smart batteries.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            """
            query SmartBatteries {
                smartBatteries {
                    brand
                    capacity
                    createdAt
                    externalReference
                    id
                    maxChargePower
                    maxDischargePower
                    provider
                    updatedAt
                    __typename
                }
            }
            """,
            "SmartBatteries",
        )

        try:
            _LOGGER.debug("Querying smart batteries")
            response = await self._query(query)
        except SmartTradingNotEnabledException as e:
            _LOGGER.debug("Smart trading not enabled: %s", e)
            return SmartBatteries([])
        except Exception as e:
            _LOGGER.error("Failed to query smart batteries: %s", e)
            return SmartBatteries([])

        # Handle empty or missing response data
        if not response:
            _LOGGER.error("Empty or missing response for 'smartBatteries'")
            return SmartBatteries([])

        if response.get("errors"):
            _LOGGER.error("Error response for 'smartBatteries': %s", response)
            return SmartBatteries([])

        data = response.get("data")

        if not isinstance(data, dict):
            _LOGGER.warning("Missing 'data' field in smartBatteries response")
            return SmartBatteries([])

        _LOGGER.debug("Response data for 'smartBatteries': %s", response)
        batteries_data = data.get("smartBatteries")

        if not isinstance(batteries_data, list):
            _LOGGER.debug("No smart batteries found")
            return SmartBatteries([])

        batteries: list[SmartBattery] = []

        for entry in batteries_data:
            if not isinstance(entry, dict):
                _LOGGER.debug("Skipping invalid smart battery entry: %s", entry)
                continue

            try:
                batteries.append(SmartBattery.from_dict(entry))
            except Exception as err:
                _LOGGER.debug("Failed to parse smart battery entry: %s", err)

        return SmartBatteries(batteries)

    async def smart_battery_details(self, device_id: str) -> SmartBatteryDetails | None:
        """Retrieve smart battery details and summary."""
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not device_id:
            raise ValueError("Missing required device_id for smart_battery_sessions")

        query = FrankEnergieQuery(
            """
                query SmartBattery($deviceId: String!) {
                    smartBattery(deviceId: $deviceId) {
                        brand
                        capacity
                        id
                        settings {
                            batteryMode
                            imbalanceTradingStrategy
                            selfConsumptionTradingAllowed
                            selfConsumptionTradingThresholdPrice
                        }
                    }
                    smartBatterySummary(deviceId: $deviceId) {
                        lastKnownStateOfCharge
                        lastKnownStatus
                        lastUpdate
                        totalResult
                    }
                }
            """,
            "SmartBattery",
            {"deviceId": device_id},
        )

        try:
            _LOGGER.debug("Querying smart battery details for device_id: %s", device_id)
            response = await self._query(query)
        except Exception as err:
            _LOGGER.error(
                "Failed to query smart battery details for device_id %s: %s",
                device_id,
                err,
            )
            return None

        if not response:
            _LOGGER.debug(
                "Empty response received for smart battery device_id: %s",
                device_id,
            )
            return None

        data: dict[str, object] | None = response.get("data")  # type: ignore[assignment]

        if not isinstance(data, dict):
            _LOGGER.debug(
                "Invalid response structure for device_id %s: missing 'data'",
                device_id,
            )
            return None

        battery_data = data.get("smartBattery")
        summary_data = data.get("smartBatterySummary")

        if not isinstance(battery_data, dict) or not isinstance(summary_data, dict):
            _LOGGER.debug(
                "Incomplete smart battery response for device_id %s",
                device_id,
            )
            raise FrankEnergieException("Incomplete response data")

        try:
            battery = SmartBattery.from_dict(battery_data)
            summary = SmartBatterySummary.from_dict(summary_data)
        except Exception as err:
            _LOGGER.error(
                "Failed to parse smart battery response for device_id %s: %s",
                device_id,
                err,
            )
            return None

        return SmartBatteryDetails(
            smart_battery=battery,
            smart_battery_summary=summary,
        )

    async def smart_battery_sessions(
        self, device_id: str, start_date: date, end_date: date
    ) -> SmartBatterySessions | None:
        """List smart battery sessions for a device.

        Returns a list of all smart battery sessions for a device.

        Full query:
        query SmartBatterySessions($startDate: String!, $endDate: String!, $deviceId: String!) {
            smartBatterySessions(
                startDate: $startDate
                endDate: $endDate
                deviceId: $deviceId
            ) {
                deviceId
                fairUsePolicyVerified
                periodEndDate
                periodEpexResult
                periodFrankSlim
                periodImbalanceResult
                periodStartDate
                periodTotalResult
                periodTradeIndex
                periodTradingResult
                sessions {
                    cumulativeTradingResult
                    cumulativeResult
                    date
                    tradingResult
                    result
                    status
                    tradeIndex
                }
                totalTradingResult
            }
        }
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not device_id:
            raise ValueError("Missing required device_id for smart_battery_sessions")

        query = FrankEnergieQuery(
            """
                query SmartBatterySessions($startDate: String!, $endDate: String!, $deviceId: String!) {
                    smartBatterySessions(
                        startDate: $startDate
                        endDate: $endDate
                        deviceId: $deviceId
                    ) {
                        deviceId
                        fairUsePolicyVerified
                        periodEndDate
                        periodEpexResult
                        periodFrankSlim
                        periodImbalanceResult
                        periodStartDate
                        periodTotalResult
                        periodTradeIndex
                        periodTradingResult
                        sessions {
                            cumulativeResult
                            date
                            result
                            status
                            tradeIndex
                        }
                    }
                }
            """,
            "SmartBatterySessions",
            {
                "deviceId": device_id,
                "startDate": start_date.isoformat(),  # Ensures proper ISO 8601 format
                "endDate": end_date.isoformat(),  # Ensures proper ISO 8601 format
            },
        )

        try:
            _LOGGER.debug("Querying smart battery sessions for device_id: %s", device_id)
            response = await self._query(query)
            _LOGGER.debug("SmartBatterySessions Response: %s", response)
        except Exception as e:
            _LOGGER.error("Failed to query smart battery sessions: %s", e)
            return None

        return SmartBatterySessions.from_dict(response)

    SMART_PV_SYSTEMS_QUERY = """
        query SmartPvSystems {
            smartPvSystems {
                brand
                connectionEAN
                createdAt
                deletedAt
                displayName
                externalReference
                id
                inverterSerialNumbers
                model
                onboardingStatus
                provider
                steeringStatus
                updatedAt
            }
        }
    """
    SMART_PV_SYSTEMS_OPERATIONNAME = "SmartPvSystems"
    SMART_PV_SYSTEMS_VARIABLES = {}

    async def smart_pv_systems(self) -> SmartPvSystems | None:
        """Get the users smart PV systems.

        Returns a collection of smart PV systems.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            self.SMART_PV_SYSTEMS_QUERY,
            self.SMART_PV_SYSTEMS_OPERATIONNAME,
            self.SMART_PV_SYSTEMS_VARIABLES,
        )

        response = await self._query(query)
        return SmartPvSystems.from_dict(response)

    SMART_PV_SYSTEM_SUMMARY_QUERY = """
        query SmartPvSystemSummary($deviceId: String!) {
            smartPvSystemSummary(deviceId: $deviceId) {
                operationalStatus
                operationalStatusTimestamp
                steeringStatus
                totalBonus
            }
        }
    """
    SMART_PV_SYSTEM_SUMMARY_OPERATIONNAME = "SmartPvSystemSummary"

    async def smart_pv_system_summary(self, device_id: str) -> SmartPvSystemSummary | None:
        """Get the summary for a specific smart PV system.

        Returns summary data for the PV system.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        if not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("device_id must be a non-empty string")

        query = FrankEnergieQuery(
            self.SMART_PV_SYSTEM_SUMMARY_QUERY,
            self.SMART_PV_SYSTEM_SUMMARY_OPERATIONNAME,
            {"deviceId": device_id},
        )

        response = await self._query(query)
        return SmartPvSystemSummary.from_dict(response)

    USER_SMART_FEED_IN_QUERY = """
        query UserSmartFeedIn {
            userSmartFeedIn {
                hasAcceptedTerms
                isActivated
                isAppOnboardingAvailable
                isAvailableInCountry
                userCreatedAt
                userId
            }
        }
    """
    USER_SMART_FEED_IN_OPERATIONNAME = "UserSmartFeedIn"
    USER_SMART_FEED_IN_VARIABLES = {}

    async def user_smart_feed_in(self) -> UserSmartFeedInStatus | None:
        """Get the users smart feed-in service status.

        Returns user smart feed-in status.
        """

        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            self.USER_SMART_FEED_IN_QUERY,
            self.USER_SMART_FEED_IN_OPERATIONNAME,
            self.USER_SMART_FEED_IN_VARIABLES,
        )

        response = await self._query(query)
        return UserSmartFeedInStatus.from_dict(response)

    ENODE_VEHICLES_QUERY = """
        query EnodeVehicles {
            enodeVehicles {
                canSmartCharge
                chargeSettings {
                    calculatedDeadline
                    deadline
                    hourFriday
                    hourMonday
                    hourSaturday
                    hourSunday
                    hourThursday
                    hourTuesday
                    hourWednesday
                    id
                    isSmartChargingEnabled
                    isSolarChargingEnabled
                    maxChargeLimit
                    minChargeLimit
                }
                chargeState {
                    batteryCapacity
                    batteryLevel
                    chargeLimit
                    chargeRate
                    chargeTimeRemaining
                    isCharging
                    isFullyCharged
                    isPluggedIn
                    lastUpdated
                    powerDeliveryState
                    range
                }
                id
                information {
                    brand
                    model
                    vin
                    year
                }
                interventions {
                    description
                    title
                }
                isReachable
                lastSeen
            }
        }
        """
    ENODE_VEHICLES_OPERATIONNAME = "EnodeVehicles"
    ENODE_VEHICLES_VARIABLES = {}

    async def enode_vehicles(self) -> EnodeVehicles | None:
        """Get the users enode vehicles.
        For this to work, the user must have a enode vehicle connected to their account and smart-trading must be enabled.

        Returns a list of all enode vehicles.
        """
        if not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")

        query = FrankEnergieQuery(
            self.ENODE_VEHICLES_QUERY,
            self.ENODE_VEHICLES_OPERATIONNAME,
            self.ENODE_VEHICLES_VARIABLES,
        )

        try:
            _LOGGER.debug("Querying enode vehicles")
            response = await self._query(query)
        except SmartChargingNotEnabledException as e:
            _LOGGER.debug("Smart charging not enabled: %s", e)
            return None
        except Exception as e:
            _LOGGER.error("Failed to query enode vehicles: %s", e)
            return None

        # Handle empty or missing response data
        # missing response is hanled in _query
        # if not response:
        #     _LOGGER.warning("Empty or missing GraphQL response for 'enodeVehicles'")
        #     return None

        # errors are hanled in _query
        # if response.get("errors"):
        #     _LOGGER.error("Error response for 'enodeVehicles': %s", response)
        #     return None

        if not response.get("data"):
            _LOGGER.debug("Empty or missing GraphQL response for 'enodeVehicles'")
            # return {}
            return None

        _LOGGER.debug("Response data for 'enodeVehicles': %s", response)
        # vehicles_data = response.get("data", {}).get("enodeVehicles", {})
        vehicles_data = response["data"]["enodeVehicles"]

        if not vehicles_data:
            _LOGGER.debug("No enode vehicles found")
            return EnodeVehicles([])

        try:
            enode_vehicles = [EnodeVehicle.from_dict(v) for v in vehicles_data]
        except (KeyError, ValueError, TypeError) as err:
            _LOGGER.error("Failed to parse enode vehicles: %s", err)
            return EnodeVehicles([])

        return EnodeVehicles(enode_vehicles)

    def _validate_not_future_date(self, value: date) -> None:
        if value > datetime.now(UTC).date():
            raise ValueError("De 'start_date' mag niet in de toekomst liggen.")

    def _validate_start_date_format(self, start_date: str | date) -> None:
        if isinstance(start_date, date):
            start_date = start_date.isoformat()

        if not re.fullmatch(r"\d{4}(-\d{2}){0,2}", start_date):
            raise ValueError("De 'start_date' moet een formaat hebben zoals 'YYYY', 'YYYY-MM' of 'YYYY-MM-DD'.")

        if len(start_date) == 10:  # volledige datum
            try:
                date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                if date_obj > datetime.now(UTC).date():
                    raise ValueError("De 'start_date' mag niet in de toekomst liggen.")
            except ValueError as e:
                raise ValueError(f"De 'start_date' heeft geen geldig datumformaat: {e}") from e

    def introspect_schema(self) -> dict[str, Any]:
        """Introspect the GraphQL schema."""
        import requests

        query = """
            query IntrospectionQuery {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
        """
        response = requests.post(self.DATA_URL, json={"query": query}, timeout=10)
        response.raise_for_status()
        return response.json()

    def get_diagnostic_data(self) -> str:
        """Get diagnostic data."""
        return "Diagnostic data"

    async def __aenter__(self):
        """Async enter.

        Returns:
            The FrankEnergie object.
        """
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        """Async exit.

        Args:
            _exc_info: Exec type.
        """
        await self.close()
