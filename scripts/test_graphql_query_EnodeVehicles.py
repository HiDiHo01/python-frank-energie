# Description: Test GraphQL query to Frank Energie API.
#   - The code snippet is used to test the GraphQL query to the Frank Energie API.
import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Optional

import aiohttp
import jwt
from aiohttp import ClientError, ClientSession
from dotenv import load_dotenv

# Laad gevoelige gegevens uit een .env-bestand
load_dotenv()

_LOGGER = logging.getLogger(__name__)
# GRAPHQL_URL = "https://graphql.frankenergie.nl"
GRAPHQL_URL = "https://frank-graphql-prod.graphcdn.app/"

EMAIL = os.getenv("FRANK_ENERGIE_EMAIL")
PASSWORD = os.getenv("FRANK_ENERGIE_PASSWORD")
SITE_REFERENCE = os.getenv("FRANK_ENERGIE_SITE_REFERENCE")

DATA_QUERY = """
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
DATA_OPERATIONNAME = "EnodeVehicles"
# DATA_VARIABLES = {"siteReference": SITE_REFERENCE, "date": str(date.today().replace(day=1))}
DATA_VARIABLES = {}

LOGIN_QUERY = """
    mutation Login($email: String!, $password: String!) {
        login(email: $email, password: $password) {
            authToken
            refreshToken
        }
    }
"""


class FrankEnergieException(Exception):
    """Base exception."""


class AuthRequiredException(FrankEnergieException):
    """Authentication required for this request."""


class AuthException(FrankEnergieException):
    """Authentication/login failed."""


class FrankEnergieQuery:
    def __init__(self, query: str, operation_name: str, variables: Optional[dict[str, Any]] = None):
        self.query = query
        self.operation_name = operation_name
        self.variables = variables if variables is not None else {}
        pass

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "operationName": self.operation_name,
            "variables": self.variables,
        }


@dataclass
class Authentication:
    """Authentication data."""
    authToken: str
    refreshToken: str

    @staticmethod
    def from_dict(data: dict[str, str]) -> 'Authentication':
        """Parse authentication response from the API."""
        _LOGGER.debug("Authentication response: %s", data)

        if "errors" in data:
            raise AuthException(data["errors"][0].get("message", "Authentication failed"))

        payload = data.get("data", {}).get("login") or data.get("data", {}).get("renewToken")
        if not payload:
            raise AuthException("Unexpected authentication response")

        return Authentication(
            authToken=payload["authToken"],
            refreshToken=payload["refreshToken"],
        )

    @staticmethod
    def _extract_payload(data: dict) -> Optional[dict]:
        """Extract the login or renewToken payload from the data dictionary."""
        return data.get("data", {}).get("login") or data.get("data", {}).get("renewToken")

    def auth_token_valid(self, tz: timezone = timezone.utc) -> bool:
        """Check if the authentication token is still valid."""
        try:
            auth_data = jwt.decode(
                self.authToken,
                verify=True,
                algorithms=["HS256"],
                options={"verify_signature": False},
            )
            return datetime.fromtimestamp(auth_data["exp"], tz=tz) > datetime.now(tz=tz)
        except jwt.ExpiredSignatureError:
            _LOGGER.error("JWT token has expired")
        except jwt.PyJWTError as error:
            _LOGGER.error("JWT decoding failed: %s", error)

        return False


class FrankEnergie:
    """FrankEnergie API client."""

    DATA_URL = GRAPHQL_URL

    def __init__(self, session: Optional[ClientSession] = None):
        """Initialize the FrankEnergie client."""
        self._session = session or ClientSession()
        self._auth: Optional[Authentication] = None

    def _handle_errors(self, response: dict[str, Any]) -> None:
        """Handle errors in the API response."""
        if "errors" in response:
            error_messages = [error.get("message", "Unknown error") for error in response["errors"]]
            raise FrankEnergieException(f"API errors: {', '.join(error_messages)}")

    async def _query(self, query: FrankEnergieQuery) -> dict[str, Any]:
        """Send a GraphQL query to the API and handle errors."""
        if self._session is None:
            self._session = ClientSession()
            self._close_session = True

        headers = {"Content-Type": "application/json"}
        if self._auth and self._auth.authToken:
            headers["Authorization"] = f"Bearer {self._auth.authToken}"

        try:
            async with self._session.post(self.DATA_URL, json=query.to_dict(), headers=headers) as resp:
                resp.raise_for_status()
                response = await resp.json()

            self._handle_errors(response)
            return response

        except (asyncio.TimeoutError, ClientError) as error:
            _LOGGER.error("Request failed: %s", error, exc_info=True)
            raise FrankEnergieException(f"Request failed: {error}") from error

    async def login(self, username: str, password: str) -> Authentication:
        """Login and retrieve the authentication token."""
        if not username or not password:
            raise ValueError("Username and password must be provided.")

        query = FrankEnergieQuery(
            LOGIN_QUERY,
            "Login",
            {"email": username, "password": password},
        )

        try:
            response_data = await self._query(query)
            if "data" in response_data and "login" in response_data["data"]:
                self._auth = Authentication.from_dict(response_data)
                _LOGGER.info("Login successful, auth_token obtained.")
                return self._auth
            else:
                raise AuthException("Login response doesn't contain expected data.")
        except (ClientError, asyncio.TimeoutError) as error:
            raise AuthException(f"Login failed: {error}")

    async def test_query(self, site_reference: str, start_date: date) -> dict:
        """Retrieve period usage and costs."""
        if not self._auth:
            raise AuthRequiredException("Authentication required for this request.")

        query = FrankEnergieQuery(
            DATA_QUERY,
            DATA_OPERATIONNAME,
            DATA_VARIABLES,
        )

        return await self._query(query)


async def main():
    """Main function to authenticate and fetch GraphQL data."""
    async with aiohttp.ClientSession() as session:
        client = FrankEnergie(session)
        try:
            auth = await client.login(EMAIL, PASSWORD)
            if not auth:
                raise AuthException("Authentication failed")
            print("Authentication successful!")

#             if self._auth.auth_token_valid():
            start_date = str(date.today().replace(day=1))  # Eerste dag van de maand
            data = await client.test_query(SITE_REFERENCE, start_date)

            print("GraphQL Response:")
            print(data)

        except Exception as e:
            print(f"Error: {e}")

        data = {'data': {'enodeVehicles': [{'canSmartCharge': True, 'chargeSettings': {'calculatedDeadline': '2025-07-23T05:00:00.000Z', 'deadline': '2025-06-13T10:00:00.000Z', 'hourFriday': 420, 'hourMonday': 420, 'hourSaturday': 420, 'hourSunday': 420, 'hourThursday': 420, 'hourTuesday': 420, 'hourWednesday': 420, 'id': 'cmbf6o4080omz95248nylyc7r', 'isSmartChargingEnabled': True, 'isSolarChargingEnabled': False, 'maxChargeLimit': 100, 'minChargeLimit': 30}, 'chargeState': {'batteryCapacity': 86.5, 'batteryLevel': 49, 'chargeLimit': 100, 'chargeRate': None, 'chargeTimeRemaining': None, 'isCharging': False, 'isFullyCharged': False, 'isPluggedIn': False, 'lastUpdated': '2025-07-22T10:53:42.000Z', 'powerDeliveryState': 'UNPLUGGED', 'range': 173}, 'id': 'cmbf6o4080omz95248nylyc7r', 'information': {'brand': 'Audi', 'model': 'e-tron', 'vin': 'WAUZZZGE9PB016244', 'year': 2023}, 'interventions': [], 'isReachable': True, 'lastSeen': '2025-07-22T14:13:36.722Z'}, {'canSmartCharge': True, 'chargeSettings': {'calculatedDeadline': '2025-07-23T05:00:00.000Z', 'deadline': None, 'hourFriday': 420, 'hourMonday': 420, 'hourSaturday': 420, 'hourSunday': 420, 'hourThursday': 420, 'hourTuesday': 420, 'hourWednesday': 420, 'id': 'cmaoye3x2203favu7d4icx7io', 'isSmartChargingEnabled': True, 'isSolarChargingEnabled': False, 'maxChargeLimit': 100, 'minChargeLimit': 75}, 'chargeState': {'batteryCapacity': 28.9, 'batteryLevel': 63, 'chargeLimit': 100, 'chargeRate': None, 'chargeTimeRemaining': None, 'isCharging': False, 'isFullyCharged': False, 'isPluggedIn': True, 'lastUpdated': '2025-07-22T13:01:54.000Z', 'powerDeliveryState': 'PLUGGED_IN:STOPPED', 'range': 98}, 'id': 'cmaoye3x2203favu7d4icx7io', 'information': {'brand': 'MINI', 'model': 'Cooper', 'vin': 'WMW11DJ0702S08837', 'year': 2021}, 'interventions': [], 'isReachable': True, 'lastSeen': '2025-07-22T14:12:24.999Z'}]}}

if __name__ == "__main__":
    asyncio.run(main())
