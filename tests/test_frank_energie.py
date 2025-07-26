"""Test for Frank Energie."""

from datetime import datetime, timezone

import aiohttp
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
# Additional Authentication Edge Cases
#


@pytest.mark.asyncio
async def test_init_with_partial_authentication():
    """Test init with only auth_token provided."""
    api = FrankEnergie(auth_token="token_only")
    assert api.is_authenticated is False


@pytest.mark.asyncio
async def test_init_with_empty_tokens():
    """Test init with empty token strings."""
    api = FrankEnergie(auth_token="", refresh_token="")
    assert api.is_authenticated is False


@pytest.mark.asyncio
async def test_init_with_none_tokens():
    """Test init with None token values."""
    api = FrankEnergie(auth_token=None, refresh_token="refresh")
    assert api.is_authenticated is False


@pytest.mark.asyncio
async def test_login_with_empty_credentials(aresponses):
    """Test login with empty username/password."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(ValueError):
            await api.login("", "")
        await api.close()


@pytest.mark.asyncio
async def test_login_with_none_credentials(aresponses):
    """Test login with None credentials."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(ValueError):
            await api.login(None, None)
        await api.close()


@pytest.mark.asyncio
async def test_login_network_error(aresponses):
    """Test login with network error."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            status=500,
            text="Internal Server Error"
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises((aiohttp.ClientError, AuthException)):
            await api.login("user", "pass")
        await api.close()


@pytest.mark.asyncio
async def test_login_malformed_json_response(aresponses):
    """Test login with malformed JSON response."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text="invalid json {",
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises((aiohttp.ClientError, AuthException)):
            await api.login("user", "pass")
        await api.close()


@pytest.mark.asyncio
async def test_renew_token_without_authentication():
    """Test renew token without authentication."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.renew_token()
        await api.close()


@pytest.mark.asyncio
async def test_renew_token_network_error(aresponses):
    """Test renew token with network error."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            status=503,
            text="Service Unavailable"
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="auth", refresh_token="refresh")
        with pytest.raises((aiohttp.ClientError, AuthException)):
            await api.renew_token()
        await api.close()


#
# Month Summary Edge Cases
#


@pytest.mark.asyncio
async def test_month_summary_invalid_response(aresponses):
    """Test month summary with invalid response format."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text='{"data": {"monthSummary": null}}',
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises((ValueError, KeyError)):
            await api.month_summary("1234AB 10")
        await api.close()


@pytest.mark.asyncio
async def test_month_summary_server_error(aresponses):
    """Test month summary with server error."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            status=500,
            text="Internal Server Error"
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises(aiohttp.ClientError):
            await api.month_summary("1234AB 10")
        await api.close()


#
# Invoices Edge Cases
#


@pytest.mark.asyncio
async def test_invoices_invalid_response(aresponses):
    """Test invoices with invalid response format."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text='{"data": {"invoices": null}}',
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises((ValueError, KeyError)):
            await api.invoices("1234AB 10")
        await api.close()


@pytest.mark.asyncio
async def test_invoices_server_error(aresponses):
    """Test invoices with server error."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            status=404,
            text="Not Found"
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises(aiohttp.ClientError):
            await api.invoices("1234AB 10")
        await api.close()


#
# Me (User) Edge Cases
#


@pytest.mark.asyncio
async def test_me_with_none_site_reference(aresponses, snapshot: SnapshotAssertion):
    """Test me with None site reference."""
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
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        me = await api.me(None)
        await api.close()

    assert me is not None
    assert me == snapshot


@pytest.mark.asyncio
async def test_me_unauthorized_error(aresponses):
    """Test me with unauthorized error (expired token)."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            status=401,
            text="Unauthorized"
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="expired", refresh_token="b")
        with pytest.raises(aiohttp.ClientError):
            await api.me("1234AB 10")
        await api.close()


#
# Prices Edge Cases
#


@pytest.mark.asyncio
async def test_prices_with_none_dates(aresponses):
    """Test prices with None date parameters (should use defaults)."""
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
        prices = await api.prices(None, None)
        await api.close()

    assert prices.electricity is not None
    assert prices.gas is not None


@pytest.mark.asyncio
async def test_prices_server_error(aresponses):
    """Test prices with server error."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            status=503,
            text="Service Unavailable"
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(aiohttp.ClientError):
            await api.prices(
                datetime.now(timezone.utc).date(), datetime.now(timezone.utc).date()
            )
        await api.close()


@pytest.mark.asyncio
async def test_prices_with_missing_data(aresponses):
    """Test prices with missing data fields."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text='{"data": {"marketPricesElectricity": [], "marketPricesGas": []}}',
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        prices = await api.prices()
        await api.close()

    assert prices.electricity is not None
    assert len(prices.electricity.price_data) == 0
    assert prices.gas is not None
    assert len(prices.gas.price_data) == 0


#
# User Prices Edge Cases
#


@pytest.mark.asyncio
async def test_user_prices_without_authentication():
    """Test user prices without authentication."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.user_prices("1234AB 10", datetime.now(timezone.utc).date())
        await api.close()


@pytest.mark.asyncio
async def test_user_prices_with_none_date(aresponses):
    """Test user prices with None date (should use default)."""
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
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        prices = await api.user_prices("1234AB 10", None)
        await api.close()

    assert prices.electricity is not None
    assert prices.gas is not None


#
# Smart Batteries Tests
#


@pytest.mark.asyncio
async def test_smart_batteries_without_authentication():
    """Test smart batteries without authentication."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.smart_batteries()
        await api.close()


@pytest.mark.asyncio
async def test_smart_batteries_empty_response(aresponses):
    """Test smart batteries with empty response."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text='{"data": {"smartBatteries": []}}',
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        batteries = await api.smart_batteries()
        await api.close()

    assert batteries is not None
    assert len(batteries.batteries) == 0


@pytest.mark.asyncio
async def test_smart_batteries_error_response(aresponses):
    """Test smart batteries with error response."""
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
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        batteries = await api.smart_batteries()
        await api.close()

    assert batteries is not None
    assert len(batteries.batteries) == 0


#
# Smart Battery Details Tests
#


@pytest.mark.asyncio
async def test_smart_battery_details_without_authentication():
    """Test smart battery details without authentication."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.smart_battery_details("device123")
        await api.close()


@pytest.mark.asyncio
async def test_smart_battery_details_empty_device_id():
    """Test smart battery details with empty device ID."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises(ValueError):
            await api.smart_battery_details("")
        await api.close()


@pytest.mark.asyncio
async def test_smart_battery_details_none_device_id():
    """Test smart battery details with None device ID."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises(ValueError):
            await api.smart_battery_details(None)
        await api.close()


#
# Smart Battery Sessions Tests
#


@pytest.mark.asyncio
async def test_smart_battery_sessions_without_authentication():
    """Test smart battery sessions without authentication."""
    from datetime import date
    
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.smart_battery_sessions("device123", date.today(), date.today())
        await api.close()


@pytest.mark.asyncio
async def test_smart_battery_sessions_empty_device_id():
    """Test smart battery sessions with empty device ID."""
    from datetime import date
    
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises(ValueError):
            await api.smart_battery_sessions("", date.today(), date.today())
        await api.close()


#
# Enode Chargers Tests
#


@pytest.mark.asyncio
async def test_enode_chargers_without_authentication():
    """Test enode chargers without authentication returns empty dict."""
    from datetime import date
    
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        chargers = await api.enode_chargers("1234AB 10", date.today())
        await api.close()

    assert chargers == {}


@pytest.mark.asyncio
async def test_enode_chargers_empty_response(aresponses):
    """Test enode chargers with empty response."""
    from datetime import date
    
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text='{"data": {"enodeChargers": []}}',
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        chargers = await api.enode_chargers("1234AB 10", date.today())
        await api.close()

    assert chargers is not None


#
# Period Usage and Costs Tests
#


@pytest.mark.asyncio
async def test_period_usage_and_costs_without_authentication():
    """Test period usage and costs without authentication."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.period_usage_and_costs("1234AB 10", "2023-01")
        await api.close()


@pytest.mark.asyncio
async def test_period_usage_and_costs_empty_site_reference():
    """Test period usage and costs with empty site reference."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        with pytest.raises(ValueError):
            await api.period_usage_and_costs("", "2023-01")
        await api.close()


#
# User Sites Tests
#


@pytest.mark.asyncio
async def test_user_sites_without_authentication():
    """Test user sites without authentication."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.UserSites()
        await api.close()


#
# User Country Tests
#


@pytest.mark.asyncio
async def test_user_country_without_authentication():
    """Test user country without authentication."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        with pytest.raises(AuthRequiredException):
            await api.user_country()
        await api.close()


#
# Belgium Prices Tests
#


@pytest.mark.asyncio
async def test_be_prices_with_custom_dates(aresponses):
    """Test Belgium prices with custom dates."""
    from datetime import date, timedelta
    
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

    start_date = date.today()
    end_date = start_date + timedelta(days=1)

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        prices = await api.be_prices(start_date, end_date)
        await api.close()

    assert prices is not None


@pytest.mark.asyncio
async def test_be_prices_with_none_dates(aresponses):
    """Test Belgium prices with None dates (should use defaults)."""
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
        prices = await api.be_prices(None, None)
        await api.close()

    assert prices is not None


#
# Connection and Session Management
#


@pytest.mark.asyncio
async def test_close_session():
    """Test closing the session."""
    api = FrankEnergie()
    await api.close()  # Should not raise exception


@pytest.mark.asyncio
async def test_close_external_session():
    """Test closing with external session."""
    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session)
        await api.close()  # Should not close external session


@pytest.mark.asyncio
async def test_double_close():
    """Test calling close multiple times."""
    api = FrankEnergie()
    await api.close()
    await api.close()  # Should not raise exception


@pytest.mark.asyncio
async def test_context_manager():
    """Test using FrankEnergie as async context manager."""
    async with FrankEnergie() as api:
        assert api is not None
        assert not api.is_authenticated


#
# Authentication State Tests
#


@pytest.mark.asyncio
async def test_authentication_state_consistency():
    """Test authentication state remains consistent."""
    api = FrankEnergie()
    assert api.is_authenticated is False
    
    # Authentication state should not change without login
    assert api.is_authenticated is False


@pytest.mark.asyncio
async def test_authentication_after_failed_login(aresponses):
    """Test authentication state after failed login."""
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
        assert api.is_authenticated is False
        
        with pytest.raises(AuthException):
            await api.login("invalid", "credentials")
        
        # Should still be unauthenticated after failed login
        assert api.is_authenticated is False
        await api.close()


#
# GraphQL Query Tests
#


@pytest.mark.asyncio
async def test_frank_energie_query_creation():
    """Test FrankEnergieQuery creation."""
    from python_frank_energie import FrankEnergieQuery
    
    query = FrankEnergieQuery("query test", "TestOperation", {"var": "value"})
    assert query.query == "query test"
    assert query.operation_name == "TestOperation"
    assert query.variables == {"var": "value"}


@pytest.mark.asyncio
async def test_frank_energie_query_to_dict():
    """Test FrankEnergieQuery to_dict method."""
    from python_frank_energie import FrankEnergieQuery
    
    query = FrankEnergieQuery("query test", "TestOperation", {"var": "value"})
    result = query.to_dict()
    assert result == {
        "query": "query test",
        "operationName": "TestOperation",
        "variables": {"var": "value"}
    }


@pytest.mark.asyncio
async def test_frank_energie_query_none_variables():
    """Test FrankEnergieQuery with None variables."""
    from python_frank_energie import FrankEnergieQuery
    
    query = FrankEnergieQuery("query test", "TestOperation", None)
    assert query.variables == {}


@pytest.mark.asyncio
async def test_frank_energie_query_invalid_variables_type():
    """Test FrankEnergieQuery with invalid variables type."""
    from python_frank_energie import FrankEnergieQuery
    
    with pytest.raises(TypeError):
        FrankEnergieQuery("query test", "TestOperation", "invalid")


#
# User Agent Tests
#


@pytest.mark.asyncio
async def test_generate_system_user_agent():
    """Test system user agent generation."""
    user_agent = FrankEnergie.generate_system_user_agent()
    assert isinstance(user_agent, str)
    assert "FrankEnergie/" in user_agent


#
# Data Validation Tests
#


@pytest.mark.asyncio
async def test_validate_start_date_format():
    """Test date format validation."""
    from datetime import date
    
    api = FrankEnergie()
    
    # Test valid formats - these should not raise exceptions
    try:
        api._validate_start_date_format("2023")
        api._validate_start_date_format("2023-01")
        api._validate_start_date_format("2023-01-01")
        api._validate_start_date_format(date(2023, 1, 1))
    except Exception:
        pytest.fail("Valid date formats should not raise exceptions")
    
    # Test invalid formats
    with pytest.raises(ValueError):
        api._validate_start_date_format("invalid")


@pytest.mark.asyncio
async def test_validate_not_future_date():
    """Test future date validation."""
    from datetime import date, timedelta
    
    api = FrankEnergie()
    
    # Future date should raise ValueError
    future_date = date.today() + timedelta(days=1)
    with pytest.raises(ValueError):
        api._validate_not_future_date(future_date)
    
    # Past/present date should not raise exception
    try:
        api._validate_not_future_date(date.today())
    except Exception:
        pytest.fail("Present date should not raise exception")


#
# Introspection Tests
#


@pytest.mark.asyncio
async def test_introspect_schema():
    """Test schema introspection."""
    api = FrankEnergie()
    
    # This test might require actual network access or mocking
    # For now, just test that the method exists
    assert hasattr(api, 'introspect_schema')
    assert callable(api.introspect_schema)


#
# Diagnostic Data Tests
#


@pytest.mark.asyncio
async def test_get_diagnostic_data():
    """Test diagnostic data retrieval."""
    api = FrankEnergie()
    
    # Test that the method exists and returns expected type
    diagnostic_data = api.get_diagnostic_data()
    assert isinstance(diagnostic_data, str)