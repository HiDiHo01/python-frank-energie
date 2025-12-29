"""Test for Frank Energie."""

from datetime import datetime, timezone

import aiohttp
import pytest_socket
import pytest
from syrupy.assertion import SnapshotAssertion

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthException, AuthRequiredException

from . import load_fixtures

SIMPLE_DATA_URL = "frank-graphql-prod.graphcdn.app"


@pytest.mark.asyncio
async def test_init_without_authentication():
    """Test init without authentication."""
    api = FrankEnergie()
    assert api.is_authenticated is False


@pytest.mark.asyncio
async def test_init_with_authentication():
    """Test init with authentication."""
    api = FrankEnergie(auth_token="a", refresh_token="b")  # noqa: S106
    assert api.is_authenticated is True


#
# Login tests
#
@pytest.mark.asyncio
@pytest.mark.allow_socket  # <-- add this marker
async def test_login(aresponses):
    """Test login."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("authentication.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        auth = await api.login("a", "b")  # noqa: S106
        await api.close()

    assert api.is_authenticated is True
    assert auth.authToken == "hello"
    assert auth.refreshToken == "world"


@pytest.mark.asyncio
async def test_login_invalid_credentials(aresponses):
    """Test login with invalid credentials."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("response_with_error.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthException):
            await api.login("a", "b")  # noqa: S106
        await api.close()


@pytest.mark.asyncio
async def test_login_invalid_response(aresponses):
    """Test login with invalid response."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text="{}",
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthException):
            await api.login("a", "b")  # noqa: S106
        await api.close()


#
# RenewToken tests
#


@pytest.mark.asyncio
async def test_renew_token(aresponses):
    """Test login."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("authentication.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, "a", "b")  # noqa: S106
        auth = await api.renew_token()
        await api.close()

    assert api.is_authenticated is True
    assert auth.authToken == "hello"
    assert auth.refreshToken == "world"


@pytest.mark.asyncio
async def test_renew_token_invalid_credentials(aresponses):
    """Test login with invalid credentials."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("response_with_error.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, "a", "b")  # noqa: S106
        with pytest.raises(AuthException):
            await api.renew_token()
        await api.close()


@pytest.mark.asyncio
async def test_renew_token_invalid_response(aresponses):
    """Test login with invalid response."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text="{}",
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, "a", "b")  # noqa: S106
        with pytest.raises(AuthException):
            await api.renew_token()
        await api.close()


#
# Month Summary
#


@pytest.mark.asyncio
async def test_month_summary(aresponses, snapshot: SnapshotAssertion):
    """Test request with authentication."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("month_summary.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        summary = await api.month_summary("1234AB 10")
        await api.close()

    assert summary is not None
    assert summary == snapshot


@pytest.mark.asyncio
async def test_month_summary_without_authentication(aresponses):
    """Test request without authentication.

    'month_summary' request requires authentication.
    """
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.month_summary("1234AB 10")
        await api.close()


#
# Invoices
#


@pytest.mark.asyncio
async def test_invoices(aresponses, snapshot: SnapshotAssertion):
    """Test request with authentication."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("invoices.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        invoices = await api.invoices("1234AB 10")
        await api.close()

    assert invoices is not None
    assert invoices == snapshot


@pytest.mark.asyncio
async def test_invoices_without_authentication(aresponses):
    """Test request without authentication.

    'invoices' request requires authentication.
    """
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.invoices("1234AB 10")
        await api.close()


#
# Me
#


@pytest.mark.asyncio
async def test_me(aresponses, snapshot: SnapshotAssertion):
    """Test request with authentication."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("me.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        me = await api.me("1234AB 10")
        await api.close()

    assert me is not None
    assert me == snapshot


@pytest.mark.asyncio
async def test_me_without_authentication(aresponses):
    """Test request without authentication.

    'user' request requires authentication.
    """
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.me("1234AB 10")
        await api.close()


#
# Prices
#


@pytest.mark.asyncio
async def test_prices(aresponses):
    """Test request without authentication.

    'prices' request does not require authentication.
    """
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("market_prices.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        prices = await api.prices(
            datetime.now(timezone.utc), datetime.now(timezone.utc)
        )
        await api.close()

    assert prices.electricity is not None
    assert len(prices.electricity.price_data) == 24

    assert prices.gas is not None
    assert len(prices.gas.price_data) == 24


@pytest.mark.asyncio
async def test_user_prices(aresponses):
    """Test request with authentication.

    'prices' request does not require authentication.
    """
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("customer_market_prices.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")  # noqa: S106
        prices = await api.user_prices(datetime.now(timezone.utc), "1234AB 10")
        await api.close()

    assert prices.electricity is not None
    assert len(prices.electricity.price_data) == 24

    assert prices.gas is not None
    assert len(prices.gas.price_data) == 24


#
# Additional comprehensive unit tests for FrankEnergie API implementation
# Testing framework: pytest with aresponses (following existing patterns)
#

# Import additional required modules for comprehensive testing
from unittest.mock import patch, AsyncMock
from datetime import timedelta
from python_frank_energie.frank_energie import FrankEnergieQuery, sanitize_query, VERSION
from python_frank_energie.exceptions import (
    SmartTradingNotEnabledException,
    SmartChargingNotEnabledException,
    FrankEnergieException,
    NetworkError,
)


#
# FrankEnergieQuery class tests
#

class TestFrankEnergieQueryClass:
    """Test cases for FrankEnergieQuery class functionality."""

    def test_frank_energie_query_init_valid_parameters(self):
        """Test FrankEnergieQuery initialization with valid parameters."""
        query = "query { test }"
        operation_name = "TestOperation"
        variables = {"var1": "value1", "var2": 42}

        frank_query = FrankEnergieQuery(query, operation_name, variables)

        assert frank_query.query == query
        assert frank_query.operation_name == operation_name
        assert frank_query.variables == variables

    def test_frank_energie_query_init_no_variables(self):
        """Test FrankEnergieQuery initialization without variables."""
        query = "query { test }"
        operation_name = "TestOperation"

        frank_query = FrankEnergieQuery(query, operation_name)

        assert frank_query.query == query
        assert frank_query.operation_name == operation_name
        assert frank_query.variables == {}

    def test_frank_energie_query_init_none_variables(self):
        """Test FrankEnergieQuery initialization with None variables."""
        query = "query { test }"
        operation_name = "TestOperation"

        frank_query = FrankEnergieQuery(query, operation_name, None)

        assert frank_query.query == query
        assert frank_query.operation_name == operation_name
        assert frank_query.variables == {}

    def test_frank_energie_query_init_invalid_variables_type(self):
        """Test FrankEnergieQuery initialization with invalid variables type."""
        query = "query { test }"
        operation_name = "TestOperation"

        with pytest.raises(TypeError, match="The 'variables' argument must be a dictionary"):
            FrankEnergieQuery(query, operation_name, "invalid_variables")

    def test_frank_energie_query_to_dict(self):
        """Test FrankEnergieQuery to_dict method."""
        query = "query { test }"
        operation_name = "TestOperation"
        variables = {"var1": "value1"}

        frank_query = FrankEnergieQuery(query, operation_name, variables)
        result = frank_query.to_dict()

        expected = {
            "query": query,
            "operationName": operation_name,
            "variables": variables
        }
        assert result == expected

    def test_frank_energie_query_to_dict_empty_variables(self):
        """Test FrankEnergieQuery to_dict method with empty variables."""
        query = "query { test }"
        operation_name = "TestOperation"

        frank_query = FrankEnergieQuery(query, operation_name)
        result = frank_query.to_dict()

        expected = {
            "query": query,
            "operationName": operation_name,
            "variables": {}
        }
        assert result == expected


#
# sanitize_query function tests
#

class TestSanitizeQueryFunction:
    """Test cases for sanitize_query function."""

    def test_sanitize_query_with_password(self):
        """Test sanitize_query masks password in variables."""
        query = FrankEnergieQuery(
            "mutation Login",
            "Login",
            {"email": "test@example.com", "password": "secret123"}
        )

        result = sanitize_query(query)

        assert result["variables"]["email"] == "test@example.com"
        assert result["variables"]["password"] == "****"

    def test_sanitize_query_without_password(self):
        """Test sanitize_query with no password in variables."""
        query = FrankEnergieQuery(
            "query Test",
            "Test",
            {"email": "test@example.com", "user_id": "123"}
        )

        result = sanitize_query(query)

        assert result["variables"]["email"] == "test@example.com"
        assert result["variables"]["user_id"] == "123"
        assert "password" not in result["variables"]

    def test_sanitize_query_empty_variables(self):
        """Test sanitize_query with empty variables."""
        query = FrankEnergieQuery("query Test", "Test", {})

        result = sanitize_query(query)

        assert result["variables"] == {}


#
# Authentication and session management tests
#

class TestFrankEnergieAuthenticationExtended:
    """Extended authentication-related functionality tests."""

    def test_frank_energie_auth_property_deprecation_warning(self):
        """Test auth property triggers deprecation warning."""
        client = FrankEnergie()

        with patch('python_frank_energie.frank_energie._LOGGER') as mock_logger:
            client.auth
            mock_logger.error.assert_called_once_with(
                "Using .auth directly is deprecated. Use .is_authenticated instead."
            )

    def test_frank_energie_is_authenticated_false_no_token(self):
        """Test is_authenticated returns False when auth exists but no token."""
        from python_frank_energie.authentication import Authentication
        client = FrankEnergie()
        client._auth = Authentication(None, "refresh_token")

        assert client.is_authenticated is False

    @pytest.mark.asyncio
    async def test_frank_energie_login_invalid_empty_credentials(self):
        """Test login with empty username or password."""
        client = FrankEnergie()

        with pytest.raises(ValueError, match="Username and password must be provided"):
            await client.login("", "password")

        with pytest.raises(ValueError, match="Username and password must be provided"):
            await client.login("username", "")

    @pytest.mark.asyncio
    async def test_frank_energie_renew_token_not_authenticated(self):
        """Test renew_token when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException, match="Authentication is required"):
            await client.renew_token()

    @pytest.mark.asyncio
    async def test_frank_energie_login_none_response_handling(self):
        """Test login with None response from query."""
        client = FrankEnergie()

        with patch.object(client, '_query', return_value=None):
            result = await client.login("test@example.com", "password")
            assert result is None


#
# System utility function tests
#

class TestFrankEnergieSystemUtilities:
    """Test system utility functions."""

    def test_frank_energie_generate_system_user_agent(self):
        """Test system user agent generation."""
        with patch('platform.system', return_value='Darwin'), \
             patch('sys.platform', 'darwin'), \
             patch('platform.release', return_value='20.6.0'):

            user_agent = FrankEnergie.generate_system_user_agent()

            expected = f"FrankEnergie/{VERSION} Darwin/20.6.0 darwin"
            assert user_agent == expected

    def test_frank_energie_generate_system_user_agent_windows(self):
        """Test system user agent generation for Windows."""
        with patch('platform.system', return_value='Windows'), \
             patch('sys.platform', 'win32'), \
             patch('platform.release', return_value='10'):

            user_agent = FrankEnergie.generate_system_user_agent()

            expected = f"FrankEnergie/{VERSION} Windows/10 win32"
            assert user_agent == expected

    def test_frank_energie_generate_system_user_agent_linux(self):
        """Test system user agent generation for Linux."""
        with patch('platform.system', return_value='Linux'), \
             patch('sys.platform', 'linux'), \
             patch('platform.release', return_value='5.4.0'):

            user_agent = FrankEnergie.generate_system_user_agent()

            expected = f"FrankEnergie/{VERSION} Linux/5.4.0 linux"
            assert user_agent == expected


#
# Session management tests
#

class TestFrankEnergieSessionManagement:
    """Test session management functionality."""

    @pytest.mark.asyncio
    async def test_frank_energie_ensure_session_creates_new(self):
        """Test _ensure_session creates new session when none exists."""
        client = FrankEnergie()

        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock(spec=aiohttp.ClientSession)
            mock_session_class.return_value = mock_session

            await client._ensure_session()

            assert client._session == mock_session
            assert client._close_session is True
            mock_session_class.assert_called_once()

    @pytest.mark.asyncio
    async def test_frank_energie_ensure_session_keeps_existing(self):
        """Test _ensure_session keeps existing session."""
        mock_session = AsyncMock(spec=aiohttp.ClientSession)
        client = FrankEnergie(clientsession=mock_session)

        await client._ensure_session()

        assert client._session == mock_session

    @pytest.mark.asyncio
    async def test_frank_energie_close_session_management(self):
        """Test session closing behavior."""
        client = FrankEnergie()
        mock_session = AsyncMock(spec=aiohttp.ClientSession)
        client._session = mock_session
        client._close_session = True

        await client.close()

        mock_session.close.assert_called_once()
        assert client._session is None
        assert client._close_session is False

    @pytest.mark.asyncio
    async def test_frank_energie_async_context_manager(self):
        """Test async context manager functionality."""
        client = FrankEnergie()

        with patch.object(client, 'close') as mock_close:
            async with client as ctx_client:
                assert ctx_client is client
            mock_close.assert_called_once()


#
# Error handling tests
#

class TestFrankEnergieErrorHandling:
    """Test comprehensive error handling functionality."""

    def test_frank_energie_handle_errors_no_response(self):
        """Test _handle_errors with no response."""
        client = FrankEnergie()

        # Should not raise any exception
        client._handle_errors(None)
        client._handle_errors({})

    def test_frank_energie_handle_errors_no_errors(self):
        """Test _handle_errors with response but no errors."""
        client = FrankEnergie()
        response = {"data": {"test": "value"}}

        # Should not raise any exception
        client._handle_errors(response)

    def test_frank_energie_handle_errors_invalid_password(self):
        """Test _handle_errors with invalid password error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "user-error:password-invalid"}
            ]
        }

        with pytest.raises(AuthException, match="Invalid password"):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_not_authorized(self):
        """Test _handle_errors with not authorized error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "user-error:auth-not-authorised"}
            ]
        }

        with pytest.raises(AuthException, match="Not authorized"):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_auth_required(self):
        """Test _handle_errors with auth required error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "user-error:auth-required"}
            ]
        }

        with pytest.raises(AuthRequiredException, match="Authentication required"):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_graphql_validation(self):
        """Test _handle_errors with GraphQL validation error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "Graphql validation error"}
            ]
        }

        with pytest.raises(FrankEnergieException, match="Request failed: Graphql validation error"):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_smart_trading_not_enabled(self):
        """Test _handle_errors with smart trading not enabled error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "user-error:smart-trading-not-enabled"}
            ]
        }

        with pytest.raises(SmartTradingNotEnabledException):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_smart_charging_not_enabled(self):
        """Test _handle_errors with smart charging not enabled error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "user-error:smart-charging-not-enabled"}
            ]
        }

        with pytest.raises(SmartChargingNotEnabledException):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_no_marketprices_found(self):
        """Test _handle_errors with no market prices found (should not raise)."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "No marketprices found for segment ABC"}
            ]
        }

        # Should not raise any exception
        client._handle_errors(response)

    def test_frank_energie_handle_errors_no_connections_found(self):
        """Test _handle_errors with no connections found error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "No connections found for user 123"}
            ]
        }

        with pytest.raises(FrankEnergieException, match="Request failed: No connections found for user 123"):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_request_not_supported_in_country(self):
        """Test _handle_errors with request not supported in country error."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "request-error:request-not-supported-in-country"}
            ]
        }

        with pytest.raises(FrankEnergieException, match="Request not supported in the user's country"):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_multiple_errors(self):
        """Test _handle_errors with multiple errors in response."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "user-error:password-invalid"},
                {"message": "user-error:auth-required"}
            ]
        }

        # Should raise the first error encountered
        with pytest.raises(AuthException, match="Invalid password"):
            client._handle_errors(response)

    def test_frank_energie_handle_errors_base_niet_aanwezig(self):
        """Test _handle_errors with Base niet aanwezig error (should not raise)."""
        client = FrankEnergie()
        response = {
            "errors": [
                {
                    "message": "'Base' niet aanwezig in prijzen verzameling",
                    "path": ["marketPrices", "electricityPrices", 0]
                }
            ]
        }

        # Should not raise any exception, just log
        client._handle_errors(response)

    def test_frank_energie_handle_errors_unhandled_error(self):
        """Test _handle_errors with unhandled error message."""
        client = FrankEnergie()
        response = {
            "errors": [
                {"message": "Some unknown error message"}
            ]
        }

        # Should not raise exception but should log error
        with patch('python_frank_energie.frank_energie._LOGGER') as mock_logger:
            client._handle_errors(response)
            mock_logger.error.assert_called()


#
# Validation helper method tests
#

class TestFrankEnergieValidationHelpers:
    """Test validation helper methods."""

    def test_frank_energie_validate_not_future_date_valid(self):
        """Test _validate_not_future_date with valid date."""
        client = FrankEnergie()

        yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)

        # Should not raise any exception
        client._validate_not_future_date(yesterday)

    def test_frank_energie_validate_not_future_date_future(self):
        """Test _validate_not_future_date with future date."""
        client = FrankEnergie()

        tomorrow = datetime.now(timezone.utc).date() + timedelta(days=1)

        with pytest.raises(ValueError, match="De 'start_date' mag niet in de toekomst liggen"):
            client._validate_not_future_date(tomorrow)

    def test_frank_energie_validate_start_date_format_valid_formats(self):
        """Test _validate_start_date_format with valid formats."""
        from datetime import date
        client = FrankEnergie()

        # Valid formats should not raise exceptions
        client._validate_start_date_format("2023")
        client._validate_start_date_format("2023-01")
        client._validate_start_date_format("2023-01-15")
        client._validate_start_date_format(date(2023, 1, 15))

    def test_frank_energie_validate_start_date_format_invalid_format(self):
        """Test _validate_start_date_format with invalid format."""
        client = FrankEnergie()

        with pytest.raises(ValueError, match="De 'start_date' moet een formaat hebben"):
            client._validate_start_date_format("invalid-date-format")

    def test_frank_energie_validate_start_date_format_future_date(self):
        """Test _validate_start_date_format with future date."""
        client = FrankEnergie()

        future_date = (datetime.now(timezone.utc).date() + timedelta(days=30)).isoformat()

        with pytest.raises(ValueError, match="De 'start_date' mag niet in de toekomst liggen"):
            client._validate_start_date_format(future_date)

    def test_frank_energie_validate_start_date_format_invalid_date(self):
        """Test _validate_start_date_format with invalid date string."""
        client = FrankEnergie()

        with pytest.raises(ValueError, match="De 'start_date' heeft geen geldig datumformaat"):
            client._validate_start_date_format("2023-13-45")  # Invalid month and day


#
# API endpoint authentication requirement tests
#

class TestFrankEnergieAPIEndpointsAuth:
    """Test API endpoint methods with authentication requirements."""

    @pytest.mark.asyncio
    async def test_frank_energie_meter_readings_not_authenticated(self):
        """Test meter readings when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException, match="Authentication is required"):
            await client.meter_readings("site_ref_123")

    @pytest.mark.asyncio
    async def test_frank_energie_month_summary_not_authenticated(self):
        """Test month summary when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException, match="Authentication is required"):
            await client.month_summary("site_ref_123")

    @pytest.mark.asyncio
    async def test_frank_energie_invoices_not_authenticated(self):
        """Test invoices when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException, match="Authentication is required"):
            await client.invoices("site_ref_123")

    @pytest.mark.asyncio
    async def test_frank_energie_me_not_authenticated(self):
        """Test me query when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.me()

    @pytest.mark.asyncio
    async def test_frank_energie_user_sites_not_authenticated(self):
        """Test UserSites query when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.UserSites()

    @pytest.mark.asyncio
    async def test_frank_energie_user_country_not_authenticated(self):
        """Test user_country query when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.user_country()

    @pytest.mark.asyncio
    async def test_frank_energie_user_not_authenticated(self):
        """Test user query when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.user()

    @pytest.mark.asyncio
    async def test_frank_energie_user_prices_not_authenticated(self):
        """Test user prices when not authenticated."""
        from datetime import date
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.user_prices("site_ref_123", date.today())

    @pytest.mark.asyncio
    async def test_frank_energie_period_usage_and_costs_not_authenticated(self):
        """Test period usage and costs when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException, match="Authenticatie is vereist"):
            await client.period_usage_and_costs("site_ref_123", "2023-01")

    @pytest.mark.asyncio
    async def test_frank_energie_period_usage_and_costs_empty_site_reference(self):
        """Test period usage and costs with empty site reference."""
        client = FrankEnergie(auth_token="test_token")

        with pytest.raises(ValueError, match="De 'site_reference' mag niet leeg zijn"):
            await client.period_usage_and_costs("", "2023-01")

    @pytest.mark.asyncio
    async def test_frank_energie_smart_batteries_not_authenticated(self):
        """Test smart batteries when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.smart_batteries()

    @pytest.mark.asyncio
    async def test_frank_energie_smart_battery_details_not_authenticated(self):
        """Test smart battery details when not authenticated."""
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.smart_battery_details("battery_123")

    @pytest.mark.asyncio
    async def test_frank_energie_smart_battery_details_empty_device_id(self):
        """Test smart battery details with empty device ID."""
        client = FrankEnergie(auth_token="test_token")

        with pytest.raises(ValueError, match="Missing required device_id"):
            await client.smart_battery_details("")

    @pytest.mark.asyncio
    async def test_frank_energie_smart_battery_sessions_not_authenticated(self):
        """Test smart battery sessions when not authenticated."""
        from datetime import date
        client = FrankEnergie()

        with pytest.raises(AuthRequiredException):
            await client.smart_battery_sessions("battery_123", date.today(), date.today())

    @pytest.mark.asyncio
    async def test_frank_energie_smart_battery_sessions_empty_device_id(self):
        """Test smart battery sessions with empty device ID."""
        from datetime import date
        client = FrankEnergie(auth_token="test_token")

        with pytest.raises(ValueError, match="Missing required device_id"):
            await client.smart_battery_sessions("", date.today(), date.today())

    @pytest.mark.asyncio
    async def test_frank_energie_enode_chargers_not_authenticated_returns_empty(self):
        """Test enode chargers when not authenticated returns empty dict."""
        from datetime import date
        client = FrankEnergie()

        result = await client.enode_chargers("site_ref_123", date.today())

        assert result == {}


#
# Utility method tests
#

class TestFrankEnergieUtilityMethods:
    """Test utility and miscellaneous methods."""

    def test_frank_energie_introspect_schema(self):
        """Test schema introspection method."""
        from unittest.mock import Mock
        client = FrankEnergie()

        mock_response = Mock()
        mock_response.json.return_value = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query", "fields": [{"name": "me"}]}
                    ]
                }
            }
        }
        mock_response.raise_for_status.return_value = None

        with patch('requests.post') as mock_post:
            mock_post.return_value.__enter__.return_value = mock_response

            result = client.introspect_schema()

            assert "data" in result
            mock_post.assert_called_once()

    def test_frank_energie_get_diagnostic_data(self):
        """Test get_diagnostic_data method."""
        client = FrankEnergie()

        result = client.get_diagnostic_data()

        assert result == "Diagnostic data"

    def test_frank_energie_constants(self):
        """Test FrankEnergie constants."""
        assert FrankEnergie.DATA_URL == "https://frank-graphql-prod.graphcdn.app/"
        assert FrankEnergie.is_smart_charging is False
        assert VERSION is not None
        assert isinstance(VERSION, str)
        assert len(VERSION) > 0


#
# Edge cases and robustness tests
#

class TestFrankEnergieEdgeCasesAndRobustness:
    """Test edge cases and robustness scenarios."""

    @pytest.mark.asyncio
    async def test_frank_energie_query_with_invalid_query_object(self):
        """Test _query method with invalid query object."""
        client = FrankEnergie()
        mock_session = AsyncMock(spec=aiohttp.ClientSession)
        client._session = mock_session

        # Object without to_dict method
        invalid_query = {"query": "test", "operationName": "Test", "variables": {}}

        with pytest.raises(TypeError, match="Query object must implement a to_dict"):
            await client._query(invalid_query)

    @pytest.mark.asyncio
    async def test_frank_energie_empty_response_handling(self):
        """Test handling of empty responses from API."""
        client = FrankEnergie()
        mock_session = AsyncMock(spec=aiohttp.ClientSession)
        client._session = mock_session

        mock_response = AsyncMock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        mock_session.post.return_value.__aenter__.return_value = mock_response

        query = FrankEnergieQuery("query { test }", "Test")

        with patch('python_frank_energie.frank_energie._LOGGER') as mock_logger:
            result = await client._query(query)

            assert result == {}
            mock_logger.debug.assert_called_with("No response data.")

    @pytest.mark.asyncio
    async def test_frank_energie_query_logging_behavior(self):
        """Test query method logging behavior."""
        client = FrankEnergie(auth_token="test_token")
        mock_session = AsyncMock(spec=aiohttp.ClientSession)
        client._session = mock_session

        mock_response = AsyncMock()
        mock_response.json.return_value = {"data": {"test": "result"}}
        mock_response.raise_for_status.return_value = None
        mock_session.post.return_value.__aenter__.return_value = mock_response

        query = FrankEnergieQuery("query { test }", "Test", {"param": "value"})

        with patch('python_frank_energie.frank_energie._LOGGER') as mock_logger, \
             patch.object(client, '_handle_errors'):

            await client._query(query)

            # Verify logging calls
            mock_logger.debug.assert_called()
            debug_calls = mock_logger.debug.call_args_list

            # Should log headers and payload
            assert any("Request headers" in str(call) for call in debug_calls)
            assert any("Request payload" in str(call) for call in debug_calls)

    @pytest.mark.asyncio
    async def test_frank_energie_smart_battery_sessions_date_formatting(self):
        """Test smart battery sessions with proper date formatting."""
        from datetime import date
        client = FrankEnergie(auth_token="test_token")

        mock_response = {
            "data": {
                "smartBatterySessions": {
                    "deviceId": "battery_123",
                    "sessions": []
                }
            }
        }

        with patch.object(client, '_query', return_value=mock_response) as mock_query:
            start_date = date(2023, 1, 1)
            end_date = date(2023, 1, 31)

            await client.smart_battery_sessions("battery_123", start_date, end_date)

            call_args = mock_query.call_args
            query_obj = call_args[0][0]
            variables = query_obj.variables

            # Verify ISO format is used
            assert variables["startDate"] == "2023-01-01"
            assert variables["endDate"] == "2023-01-31"
            assert variables["deviceId"] == "battery_123"


#
# Platform-specific tests
#

class TestFrankEnergieWindowsPlatformHandling:
    """Test Windows-specific platform handling."""

    def test_frank_energie_windows_event_loop_policy(self):
        """Test Windows event loop policy is set."""
        import sys
        import asyncio

        original_platform = sys.platform
        try:
            sys.platform = 'win32'
            with patch('asyncio.set_event_loop_policy') as mock_set_policy:
                # Re-import the module to trigger the Windows check
                import importlib
                import python_frank_energie.frank_energie
                importlib.reload(python_frank_energie.frank_energie)

                # Verify Windows event loop policy was set
                mock_set_policy.assert_called_with(asyncio.WindowsSelectorEventLoopPolicy())
        finally:
            sys.platform = original_platform


#
# Error handling and robustness tests for API methods
#

@pytest.mark.asyncio
async def test_month_summary_exception_handling(aresponses):
    """Test month summary exception handling."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text='{"errors": [{"message": "Network error"}]}',
            status=500,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="test_token")

        with pytest.raises(FrankEnergieException, match="Failed to fetch month summary"):
            await api.month_summary("site_ref_123")

        await api.close()


@pytest.mark.asyncio
async def test_enode_chargers_empty_response_handling():
    """Test enode chargers with various empty response scenarios."""
    client = FrankEnergie(auth_token="test_token")

    # Test with None response
    with patch.object(client, '_query', return_value=None):
        result = await client.enode_chargers("site_ref_123", datetime.now().date())
        assert result == {}

    # Test with empty data
    with patch.object(client, '_query', return_value={"data": None}):
        result = await client.enode_chargers("site_ref_123", datetime.now().date())
        assert result == {}

    # Test with missing enodeChargers key
    with patch.object(client, '_query', return_value={"data": {}}):
        result = await client.enode_chargers("site_ref_123", datetime.now().date())
        assert result == {}


@pytest.mark.asyncio
async def test_smart_batteries_error_handling():
    """Test smart batteries comprehensive error handling."""
    client = FrankEnergie(auth_token="test_token")

    # Test with empty response
    with patch.object(client, '_query', return_value=None):
        result = await client.smart_batteries()
        assert len(result.batteries) == 0

    # Test with error response
    with patch.object(client, '_query', return_value={"errors": [{"message": "Some error"}]}):
        result = await client.smart_batteries()
        assert len(result.batteries) == 0

    # Test with missing data
    with patch.object(client, '_query', return_value={"data": None}):
        result = await client.smart_batteries()
        assert len(result.batteries) == 0


@pytest.mark.asyncio
async def test_smart_battery_details_incomplete_response():
    """Test smart battery details with incomplete response."""
    client = FrankEnergie(auth_token="test_token")

    mock_response = {
        "data": {
            "smartBattery": {"id": "battery_123"}
        }
    }

    with patch.object(client, '_query', return_value=mock_response), \
         pytest.raises(FrankEnergieException, match="Incomplete response data"):
        await client.smart_battery_details("battery_123")


@pytest.mark.asyncio
async def test_period_usage_and_costs_exception_handling():
    """Test period usage and costs exception handling."""
    client = FrankEnergie(auth_token="test_token")

    with patch.object(client, '_query', side_effect=NetworkError("Network error")), \
         pytest.raises(FrankEnergieException, match="Kon verbruik en kosten niet ophalen"):
        await client.period_usage_and_costs("site_ref_123", "2023-01")


# Test constants and class attributes
def test_frank_energie_version_constant():
    """Test VERSION constant is properly defined."""
    assert VERSION is not None
    assert isinstance(VERSION, str)
    assert len(VERSION) > 0
    # VERSION should follow semver pattern
    import re
    version_pattern = r'^\d{4}\.\d{1,2}\.\d{1,2}$'
    assert re.match(version_pattern, VERSION), f"VERSION '{VERSION}' should follow YYYY.M.D pattern"


def test_frank_energie_data_url_constant():
    """Test DATA_URL constant."""
    assert FrankEnergie.DATA_URL == "https://frank-graphql-prod.graphcdn.app/"


def test_frank_energie_is_smart_charging_attribute():
    """Test is_smart_charging class attribute."""
    assert FrankEnergie.is_smart_charging is False


# Test default date handling in various methods
@pytest.mark.asyncio
async def test_prices_with_default_dates():
    """Test prices method with default date handling."""
    from datetime import date, timedelta
    client = FrankEnergie()

    mock_response = {
        "data": {
            "marketPricesElectricity": [],
            "marketPricesGas": []
        }
    }

    with patch.object(client, '_query', return_value=mock_response) as mock_query:
        await client.prices()
        call_args = mock_query.call_args
        query_obj = call_args[0][0]
        variables = query_obj.variables

        today = date.today()
        tomorrow = today + timedelta(days=1)

        assert variables["startDate"] == str(today)
        assert variables["endDate"] == str(tomorrow)


@pytest.mark.asyncio
async def test_be_prices_with_default_dates():
    """Test Belgian prices method with default date handling."""
    from datetime import datetime, timezone
    client = FrankEnergie()

    mock_response = {
        "data": {
            "marketPrices": {
                "electricityPrices": [],
                "gasPrices": []
            }
        }
    }

    with patch.object(client, '_query', return_value=mock_response) as mock_query:
        await client.be_prices()
        call_args = mock_query.call_args
        query_obj = call_args[0][0]
        variables = query_obj.variables

        utc_today = datetime.now(timezone.utc).date()

        assert variables["date"] == str(utc_today)


@pytest.mark.asyncio
async def test_user_prices_date_validation():
    """Test user prices method date validation and formatting."""
    from datetime import date
    client = FrankEnergie(auth_token="test_token")

    mock_response = {
        "data": {
            "customerMarketPrices": {
                "electricityPrices": [],
                "gasPrices": []
            }
        }
    }

    with patch.object(client, '_query', return_value=mock_response) as mock_query:
        start_date = date(2023, 1, 1)
        await client.user_prices("site_ref", start_date)

        call_args = mock_query.call_args
        query_obj = call_args[0][0]
        variables = query_obj.variables

        assert variables["date"] == str(start_date)
        assert variables["siteReference"] == "site_ref"
