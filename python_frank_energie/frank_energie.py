"""FrankEnergie API implementation."""

# python_frank_energie/frank_energie.py

import asyncio
from datetime import date, datetime, timezone
from http import HTTPStatus
import re
from typing import Optional
import logging
import traceback

_LOGGER = logging.getLogger(__name__)

import aiohttp
import sys
import platform
from aiohttp import ClientSession, ClientError

from .authentication import Authentication
from .exceptions import (
    AuthException,
    AuthRequiredException,
    FrankEnergieException,
    NetworkError,
    RequestException,
    SmartTradingNotEnabledException,
    SmartChargingNotEnabledException,
)

VERSION = "2025.6.17"

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

class FrankEnergieQuery:
    """Represents a GraphQL query for the FrankEnergie API."""

    def __init__(
        self,
        query: str,
        operation_name: str,
        variables: Optional[dict[str, object]] = None,
    ) -> None:
        if variables is not None and not isinstance(variables, dict):
            raise TypeError(
                "The 'variables' argument must be a dictionary if provided."
            )

        self.query = query
        self.operation_name = operation_name
        self.variables = variables if variables is not None else {}

    def to_dict(self) -> dict[str, object]:
        """Convert the query to a dictionary suitable for GraphQL API calls."""
        return {
            "query": self.query,
            "operationName": self.operation_name,
            "variables": self.variables,
        }


def sanitize_query(query: FrankEnergieQuery) -> dict[str, object]:
    sanitized_query = query.to_dict()
    if "password" in sanitized_query["variables"]:
        sanitized_query["variables"]["password"] = "****"
    return sanitized_query


class FrankEnergie:
    """FrankEnergie API client."""

    DATA_URL = "https://frank-graphql-prod.graphcdn.app/"
    # DATA_URL = "https://graphql.frankenergie.nl/"

    def __init__(
        self,
        clientsession: Optional[ClientSession] = None,
        auth_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> None:
        """Initialize the FrankEnergie client."""
        self._session: Optional[ClientSession] = clientsession
        self._close_session: bool = clientsession is None
        self._auth: Optional[Authentication] = None

        if auth_token or refresh_token:
            self._auth = Authentication(auth_token, refresh_token)

    is_smart_charging = False

    async def close(self) -> None:
        """Close the client session if it was created internally."""
        if self._close_session and self._session is not None:
            await self._session.close()

    @property
    def auth(self) -> Optional[Authentication]:
        """Backwards compatibility for integrations accessing .auth directly."""
        _LOGGER.error(
            "Using .auth directly is deprecated. Use .is_authenticated instead."
        )
        return self._auth

    @property
    def is_authenticated(self) -> bool:
        """Check if the client is authenticated."""
        return self._auth is not None and self._auth.authToken is not None

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

    async def _query(
        self, query: FrankEnergieQuery, extra_headers: Optional[dict[str, str]] = None
    ) -> dict[str, object]:
        """Send a query to the FrankEnergie API.

        Args:
            query: The GraphQL query as a dictionary.

        Returns:
            The response from the API as a dictionary.

        Raises:
            NetworkError: If the network request fails.
            FrankEnergieException: If the request fails.
        """

        # "User-Agent": self.generate_system_user_agent(), # not working properly
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        if self._auth is not None and self._auth.authToken is not None:
            headers["Authorization"] = f"Bearer {self._auth.authToken}"

        if extra_headers:
            headers.update(extra_headers)

        _LOGGER.debug("Request headers: %s", headers)
        if isinstance(query, dict):
            _LOGGER.debug("Request payload: %s", query)
        else:
            _LOGGER.debug("Request payload: %s", query.to_dict())

        await self._ensure_session()

        try:
            if hasattr(query, "to_dict") and callable(query.to_dict):
                payload = query.to_dict()
            else:
                _LOGGER.error(
                    "Query object does not implement to_dict() method: %s", query
                )
                raise TypeError(
                    "Query object must implement a to_dict() method to be JSON serializable.",
                    query,
                )
            async with self._session.post(
                self.DATA_URL, json=payload, headers=headers, timeout=30
            ) as resp:
                resp.raise_for_status()
                response: dict[str, object] = await resp.json()

            if not response:
                _LOGGER.debug("No response data.")
                return {}

            logging.debug("Response body: %s", response)
            self._handle_errors(response)
            return response

        except (asyncio.TimeoutError, ClientError, KeyError) as error:
            _LOGGER.error("Request failed: %s", error)
            raise NetworkError(f"Request failed: {error}") from error
        except aiohttp.ClientResponseError as error:
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
        except Exception as error:
            traceback.print_exc()
            raise error

    def _process_diagnostic_data(self, response: dict[str, object]) -> None:
        """Process the diagnostic data and update the sensor state.

        Args:
            response: The API response as a dictionary.
        """
        diagnostic_data = response.get("diagnostic_data")
        if diagnostic_data:
            self._frank_energie_diagnostic_sensor.update_diagnostic_data(
                diagnostic_data
            )

    def _handle_errors(self, response: dict[str, object]) -> None:
        """Catch common error messages and raise a more specific exception.

        Args:
            response: The API response as a dictionary.
        """
        if not response:
            _LOGGER.debug("No response data.")
            return

        errors = response.get("errors")
        if not errors:
            return

        for error in errors:
            message = error["message"]
            path = error.get("path", None)
            if message == "user-error:password-invalid":
                raise AuthException("Invalid password")
            elif message == "user-error:auth-not-authorised":
                raise AuthException("Not authorized")
            elif message == "user-error:auth-required":
                raise AuthRequiredException("Authentication required")
            elif message == "Graphql validation error":
                raise FrankEnergieException("Request failed: Graphql validation error")
            elif message.startswith("No marketprices found for segment"):
                return
            elif message.startswith("No connections found for user"):
                raise FrankEnergieException("Request failed: %s" % message)
            elif message == "user-error:smart-trading-not-enabled":
                _LOGGER.debug("Smart trading is not enabled for this user.")
                raise SmartTradingNotEnabledException(
                    "Smart trading is not enabled for this user."
                )
            elif message == "user-error:smart-charging-not-enabled":
                _LOGGER.debug("Smart charging is not enabled for this user.")
                raise SmartChargingNotEnabledException(
                    "Smart charging is not enabled for this user."
                )
            elif message == "'Base' niet aanwezig in prijzen verzameling":
                _LOGGER.debug("'Base' niet aanwezig in prijzen verzameling %s.", path)
            elif message == "request-error:request-not-supported-in-country":
                _LOGGER.error("Request not supported in the user's country: %s", error)
                raise FrankEnergieException(
                    "Request not supported in the user's country"
                )
            else:
                _LOGGER.error("Unhandled error: %s", message)
                _LOGGER.error("Unhandled error in GraphQL response: %s", error)

    # ... (all other methods remain unchanged, except below)

    def _validate_start_date_format(self, start_date: str | date) -> None:
        if isinstance(start_date, date):
            start_date = start_date.isoformat()

        if not re.fullmatch(r"\d{4}(-\d{2}){0,2}", start_date):
            raise ValueError(
                "De 'start_date' moet een formaat hebben zoals 'YYYY', 'YYYY-MM' of 'YYYY-MM-DD'."
            )

        if len(start_date) == 10:  # volledige datum
            try:
                date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                if date_obj > datetime.now(timezone.utc).date():
                    raise ValueError("De 'start_date' mag niet in de toekomst liggen.")
            except ValueError as e:
                raise ValueError(
                    "De 'start_date' heeft geen geldig datumformaat: %s" % e
                ) from e

    # Removed duplicate async def close(self) at line 1721
    # Removed duplicate @property def is_authenticated(self) at line 1687
    # Removed all unused mock_response assignments in:
    #   - smart_batteries
    #   - smart_battery_details
    #   - smart_battery_sessions
    # All other methods and GraphQL query strings remain as originally defined above.

    # Introspection and get_diagnostic_data remain unchanged.
    ...