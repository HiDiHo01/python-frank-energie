"""FrankEnergie API implementation."""

# python_frank_energie/frank_energie.py

import asyncio
from datetime import date, datetime, timedelta, timezone
from http import HTTPStatus
import re
from typing import Any, Optional
import logging
import traceback

_LOGGER = logging.getLogger(__name__)

# Removed unused import: urllib.response

import aiohttp
import requests
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
from .models import (
    EnergyConsumption,
    EnodeChargers,
    Invoices,
    MarketPrices,
    Me,
    MonthSummary,
    PeriodUsageAndCosts,
    SmartBatteries,
    SmartBattery,
    SmartBatteryDetails,
    SmartBatterySessions,
    User,
    UserSites,
)

_VERSION = "2025.6.17"

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class FrankEnergieQuery:
    """Represents a GraphQL query for the FrankEnergie API."""

    def __init__(
        self,
        query: str,
        operation_name: str,
        variables: Optional[dict[str, Any]] = None,
    ) -> None:
        if variables is not None and not isinstance(variables, dict):
            raise TypeError(
                "The 'variables' argument must be a dictionary if provided."
            )
        self.query = query
        self.operation_name = operation_name
        self.variables = variables or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert the query to a dictionary suitable for GraphQL API calls."""
        return {
            "query": self.query,
            "operationName": self.operation_name,
            "variables": self.variables,
        }


def sanitize_query(query: FrankEnergieQuery) -> dict[str, Any]:
    sanitized = query.to_dict()
    if "password" in sanitized["variables"]:
        sanitized["variables"]["password"] = "****"
    return sanitized


class FrankEnergie:
    """FrankEnergie API client."""

    DATA_URL = "https://frank-graphql-prod.graphcdn.app/"

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
        system = platform.system()
        system_platform = sys.platform
        release = platform.release()
        return f"FrankEnergie/{_VERSION} {system}/{release} {system_platform}"

    async def _ensure_session(self) -> None:
        if self._session is None:
            self._session = ClientSession()
            self._close_session = True

    async def _query(
        self, query: FrankEnergieQuery, extra_headers: Optional[dict[str, str]] = None
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._auth and self._auth.authToken:
            headers["Authorization"] = f"Bearer {self._auth.authToken}"
        if extra_headers:
            headers.update(extra_headers)

        _LOGGER.debug("Request headers: %s", headers)
        if isinstance(query, dict):
            _LOGGER.debug("Request payload: %s", query)
            payload = query
        else:
            _LOGGER.debug("Request payload: %s", query.to_dict())
            if not hasattr(query, "to_dict") or not callable(query.to_dict):
                _LOGGER.error(
                    "Query object does not implement to_dict() method: %s", query
                )
                raise TypeError(
                    "Query object must implement a to_dict() method to be JSON serializable.",
                    query,
                )
            payload = query.to_dict()

        await self._ensure_session()

        try:
            async with self._session.post(
                self.DATA_URL, json=payload, headers=headers, timeout=30
            ) as resp:
                resp.raise_for_status()
                resp_data = await resp.json()

            if not resp_data:
                _LOGGER.debug("No response data.")
                return {}

            _LOGGER.debug("Response body: %s", resp_data)
            self._handle_errors(resp_data)
            return resp_data

        except (asyncio.TimeoutError, ClientError, KeyError) as error:
            _LOGGER.error("Request failed: %s", error)
            raise NetworkError(f"Request failed: {error}") from error
        except aiohttp.ClientResponseError as error:
            if error.status == HTTPStatus.UNAUTHORIZED:
                raise AuthRequiredException("Authentication required.") from error
            if error.status == HTTPStatus.FORBIDDEN:
                raise AuthException("Forbidden: Invalid credentials.") from error
            if error.status == HTTPStatus.BAD_REQUEST:
                raise RequestException("Bad request: Invalid query.") from error
            if error.status == HTTPStatus.INTERNAL_SERVER_ERROR:
                raise FrankEnergieException("Internal server error.") from error
            raise FrankEnergieException(f"Unexpected response: {error}") from error
        except Exception:
            traceback.print_exc()
            raise

    def _process_diagnostic_data(self, response: dict[str, Any]) -> None:
        diagnostic = response.get("diagnostic_data")
        if diagnostic:
            self._frank_energie_diagnostic_sensor.update_diagnostic_data(diagnostic)

    def _handle_errors(self, response: dict[str, Any]) -> None:
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
            if message == "user-error:auth-not-authorised":
                raise AuthException("Not authorized")
            if message == "user-error:auth-required":
                raise AuthRequiredException("Authentication required")
            if message == "Graphql validation error":
                raise FrankEnergieException("Request failed: Graphql validation error")
            if message.startswith("No marketprices found for segment"):
                return
            if message.startswith("No connections found for user"):
                raise FrankEnergieException(f"Request failed: {message}")
            if message == "user-error:smart-trading-not-enabled":
                _LOGGER.debug("Smart trading is not enabled for this user.")
                raise SmartTradingNotEnabledException(
                    "Smart trading is not enabled for this user."
                )
            if message == "user-error:smart-charging-not-enabled":
                _LOGGER.debug("Smart charging is not enabled for this user.")
                raise SmartChargingNotEnabledException(
                    "Smart charging is not enabled for this user."
                )
            if message == "'Base' niet aanwezig in prijzen verzameling":
                _LOGGER.debug("'Base' niet aanwezig in prijzen verzameling %s.", path)
            if message == "request-error:request-not-supported-in-country":
                _LOGGER.error("Request not supported in the user's country: %s", error)
                raise FrankEnergieException(
                    "Request not supported in the user's country"
                )
            _LOGGER.error("Unhandled error: %s", message)
            _LOGGER.error("Unhandled error in GraphQL response: %s", error)

    LOGIN_QUERY = """
        mutation Login($email: String!, $password: String!) {
            login(email: $email, password: $password) {
                authToken
                refreshToken
            }
            version
            __typename
        }
    """

    async def login(self, username: str, password: str) -> Authentication:
        if not username or not password:
            raise ValueError("Username and password must be provided.")
        query = FrankEnergieQuery(
            self.LOGIN_QUERY, "Login", {"email": username, "password": password}
        )
        try:
            resp = await self._query(query)
            if resp and resp.get("data"):
                self._auth = Authentication.from_dict(resp)
            return self._auth
        except Exception:
            traceback.print_exc()
            raise

    async def renew_token(self) -> Authentication:
        if not self._auth or not self.is_authenticated:
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
        resp = await self._query(query)
        self._auth = Authentication.from_dict(resp)
        return self._auth

    async def meter_readings(self, site_reference: str) -> EnergyConsumption:
        if not self._auth or not self.is_authenticated:
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
        resp = await self._query(query)
        return EnergyConsumption.from_dict(resp)

    async def month_summary(self, site_reference: str) -> MonthSummary:
        if not self._auth or not self.is_authenticated:
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
            resp = await self._query(query)
            return MonthSummary.from_dict(resp)
        except Exception as e:
            raise FrankEnergieException(f"Failed to fetch month summary: {e}") from e

    async def enode_chargers(
        self, site_reference: str, start_date: date
    ) -> dict[str, EnodeChargers]:
        if not self._auth or not self.is_authenticated:
            _LOGGER.debug("Skipping Enode Chargers: not authenticated.")
            return {}
        query = FrankEnergieQuery(
            """
            query EnodeChargers { ... }
            """,
            "EnodeChargers",
            {"siteReference": site_reference},
        )
        try:
            resp = await self._query(query)
            if not resp or not resp.get("data") or not resp["data"].get("enodeChargers"):
                _LOGGER.debug("No Enode Chargers data: %s", resp)
                return {}
            data = resp["data"]["enodeChargers"]
            _LOGGER.info("%s Enode Chargers Found", len(data))
            return EnodeChargers.from_dict(data)
        except Exception as error:
            _LOGGER.exception("Unexpected error during enode_chargers: %s", error)
            return {}

    async def invoices(self, site_reference: str) -> Invoices:
        if not self._auth or not self.is_authenticated:
            raise AuthRequiredException("Authentication is required.")
        query = FrankEnergieQuery(
            """
            query Invoices($siteReference: String!) { ... }
            """,
            "Invoices",
            {"siteReference": site_reference},
        )
        resp = await self._query(query)
        return Invoices.from_dict(resp)

    async def me(self, site_reference: str | None = None) -> Me:
        if not self._auth:
            raise AuthRequiredException()
        query = FrankEnergieQuery(
            """
            query Me($siteReference: String) { ... }
            """,
            "Me",
            {"siteReference": site_reference},
        )
        resp = await self._query(query)
        return Me.from_dict(resp)

    async def UserSites(self, site_reference: str | None = None) -> UserSites:
        if not self._auth:
            raise AuthRequiredException()
        query = FrankEnergieQuery(
            """
            query UserSites { ... }
            """,
            "UserSites",
            {},
        )
        resp = await self._query(query)
        return UserSites.from_dict(resp)

    async def user_country(self) -> Me:
        if not self._auth:
            raise AuthRequiredException()
        query = FrankEnergieQuery(
            """
            query UserCountry { ... }
            """,
            "UserCountry",
            {},
        )
        resp = await self._query(query)
        return Me.from_dict(resp)

    async def user(self, site_reference: str | None = None) -> User:
        if not self._auth:
            raise AuthRequiredException()
        query = FrankEnergieQuery(
            """
            query Me($siteReference: String) { ... }
            """,
            "Me",
            {"siteReference": site_reference},
        )
        resp = await self._query(query)
        return User.from_dict(resp)

    async def be_prices(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
    ) -> MarketPrices:
        if start_date is None:
            start_date = datetime.now(timezone.utc).date()
        if end_date is None:
            end_date = start_date + timedelta(days=1)
        headers = {"x-country": "BE"}
        query = FrankEnergieQuery(
            """
            query MarketPrices ($date: String!) { ... }
            """,
            "MarketPrices",
            {"date": str(start_date)},
        )
        resp = await self._query(query, extra_headers=headers)
        return MarketPrices.from_be_dict(resp)

    async def prices(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
    ) -> MarketPrices:
        if not start_date:
            start_date = date.today()
        if not end_date:
            end_date = date.today() + timedelta(days=1)
        query = FrankEnergieQuery(
            """
            query MarketPrices($startDate: Date!, $endDate: Date!) { ... }
            """,
            "MarketPrices",
            {"startDate": str(start_date), "endDate": str(end_date)},
        )
        resp = await self._query(query)
        return MarketPrices.from_dict(resp)

    async def user_prices(
        self,
        site_reference: str,
        start_date: date,
        end_date: Optional[date] = None,
    ) -> MarketPrices:
        if not self._auth:
            raise AuthRequiredException()
        if not start_date:
            start_date = date.today()
        if not end_date:
            end_date = date.today() + timedelta(days=1)
        query = FrankEnergieQuery(
            """
            query MarketPrices($date: String!, $siteReference: String!) { ... }
            """,
            "MarketPrices",
            {"date": str(start_date), "siteReference": site_reference},
        )
        resp = await self._query(query)
        return MarketPrices.from_userprices_dict(resp)

    async def period_usage_and_costs(
        self,
        site_reference: str,
        start_date: str,
    ) -> PeriodUsageAndCosts:
        if not site_reference:
            raise ValueError("De 'site_reference' mag niet leeg zijn.")
        if not self._auth:
            raise AuthRequiredException(
                "Authenticatie is vereist om deze query uit te voeren."
            )
        query = FrankEnergieQuery(
            """
            query PeriodUsageAndCosts($date: String!, $siteReference: String!) { ... }
            """,
            "PeriodUsageAndCosts",
            {"siteReference": site_reference, "date": str(start_date)},
        )
        try:
            resp = await self._query(query)
            return PeriodUsageAndCosts.from_dict(resp)
        except Exception as err:
            _LOGGER.exception(
                "Fout bij ophalen van periodUsageAndCosts voor site %s op %s: %s",
                site_reference,
                start_date,
                err,
            )
            raise FrankEnergieException(
                "Kon verbruik en kosten niet ophalen voor opgegeven periode."
            ) from err

    async def smart_batteries(self) -> SmartBatteries:
        if not self._auth:
            raise AuthRequiredException()
        query = FrankEnergieQuery(
            """
            query SmartBatteries { ... }
            """,
            "SmartBatteries",
        )
        resp = await self._query(query)
        if not resp or resp.get("errors") or not resp.get("data"):
            _LOGGER.warning("Empty or error response for smartBatteries: %s", resp)
            return SmartBatteries([])
        batteries_data = resp["data"].get("smartBatteries") or []
        try:
            batteries = [SmartBattery.from_dict(b) for b in batteries_data]
        except (KeyError, ValueError, TypeError) as err:
            _LOGGER.error("Failed to parse smart batteries: %s", err)
            return SmartBatteries([])
        return SmartBatteries(batteries)

    async def smart_battery_details(self, device_id: str) -> SmartBatteryDetails:
        if not self._auth:
            raise AuthRequiredException()
        if not device_id:
            raise ValueError("Missing required device_id for smart_battery_sessions")
        query = FrankEnergieQuery(
            """
            query SmartBattery($deviceId: String!) { ... }
            """,
            "SmartBattery",
            {"deviceId": device_id},
        )
        resp = await self._query(query)
        if not resp or "data" not in resp or "smartBattery" not in resp["data"] or "smartBatterySummary" not in resp["data"]:
            _LOGGER.debug("Incomplete response for smartBattery details: %s", resp)
            raise FrankEnergieException(
                "Incomplete response data for smart battery details"
            )
        return SmartBatteryDetails.from_dict(
            {
                "smartBattery": resp["data"]["smartBattery"],
                "smartBatterySummary": resp["data"]["smartBatterySummary"],
            }
        )

    async def smart_battery_sessions(
        self, device_id: str, start_date: date, end_date: date
    ) -> SmartBatterySessions:
        if not self._auth:
            raise AuthRequiredException()
        if not device_id:
            raise ValueError("Missing required device_id for smart_battery_sessions")
        query = FrankEnergieQuery(
            """
            query SmartBatterySessions($startDate: String!, $endDate: String!, $deviceId: String!) { ... }
            """,
            "SmartBatterySessions",
            {
                "deviceId": device_id,
                "startDate": start_date.isoformat(),
                "endDate": end_date.isoformat(),
            },
        )
        resp = await self._query(query)
        return SmartBatterySessions.from_dict(resp)

    def _validate_not_future_date(self, value: date) -> None:
        if value > datetime.now(timezone.utc).date():
            raise ValueError("De 'start_date' mag niet in de toekomst liggen.")

    def _validate_start_date_format(self, start_date: str | date) -> None:
        if isinstance(start_date, date):
            start_date = start_date.isoformat()
        if not re.fullmatch(r"\d{4}(-\d{2}){0,2}", start_date):
            raise ValueError(
                "De 'start_date' moet een formaat hebben zoals 'YYYY', 'YYYY-MM' of 'YYYY-MM-DD'."
            )
        if len(start_date) == 10:
            try:
                date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                if date_obj > datetime.now(timezone.utc).date():
                    raise ValueError("De 'start_date' mag niet in de toekomst liggen.")
            except ValueError as e:
                raise ValueError(
                    "De 'start_date' heeft geen geldig datumformaat: %s" % e
                ) from e

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        await self.close()

    def introspect_schema(self):
        query = """
            query IntrospectionQuery {
                __schema {
                    types { name fields { name } }
                }
            }
        """
        with requests.post(self.DATA_URL, json={"query": query}, timeout=10) as resp:
            resp.raise_for_status()
            return resp.json()

    def get_diagnostic_data(self):
        # Implement the logic to fetch diagnostic data from the FrankEnergie API
        return "Diagnostic data"