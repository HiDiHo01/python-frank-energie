"""Test rate-limit classification, metadata, and request behavior."""

import asyncio
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from python_frank_energie import FrankEnergie, RateLimitException, RequestException
from python_frank_energie.exceptions import (
    AuthException,
    AuthRequiredException,
    FrankEnergieException,
    RefreshTokenInvalidException,
    SmartBatteryNotFoundException,
)
from python_frank_energie.frank_energie import FrankEnergieQuery, _parse_retry_after


@pytest.fixture
def rate_limit_payload() -> dict[str, object]:
    """Return the sanitized error object reported in issue 205."""
    return {
        "errors": [
            {
                "message": "Too Many Requests",
                "locations": [{"line": 2, "column": 3}],
                "path": ["invoices"],
            }
        ]
    }


def _create_client(payload: dict[str, object]) -> tuple[FrankEnergie, MagicMock, MagicMock]:
    """Create a client with a mocked session and synchronous status checking."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json = AsyncMock(return_value=payload)
    response.headers = {}
    session = MagicMock(spec=aiohttp.ClientSession)
    session.post.return_value.__aenter__.return_value = response
    client = FrankEnergie(session, auth_token="synthetic-token")  # noqa: S106
    return client, session, response


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("", None),
        ("  ", None),
        ("120", 120.0),
        (" 120 ", 120.0),
        ("0", 0.0),
        ("-1", None),
        ("1.5", None),
        ("NaN", None),
        ("inf", None),
        ("1e3", None),
        ("not-a-date", None),
        ("١٢٠", None),
        ("9" * 400, None),
        ("Wed, 28 Oct 2026 12:02:00 GMT", 120.0),
        ("Wednesday, 28-Oct-26 12:02:00 GMT", 120.0),
        ("Wed Oct 28 14:00:00 2026", 7200.0),
        ("Wed Oct 28 11:59:00 2026", 0.0),
        ("Fri Nov  6 12:02:00 2026", 777720.0),
        ("Wed, 28 Oct 2026 11:59:00 GMT", 0.0),
        ("Wed, 28 Oct 2026 12:02:00", None),
        ("Wed, 28 Oct 2026 12:02:00 -0000", None),
    ],
)
def test_parse_retry_after(header: str | None, expected: float | None) -> None:
    """Parse valid HTTP delays and leave absent or unusable hints unknown."""
    with patch("python_frank_energie.frank_energie.datetime") as clock:
        clock.now.return_value = datetime(2026, 10, 28, 12, tzinfo=UTC)
        assert _parse_retry_after(header) == expected


@pytest.mark.parametrize("header", [None, "120", "not-a-date"])
@pytest.mark.asyncio
async def test_invoices_propagates_graphql_rate_limit(
    rate_limit_payload: dict[str, object], header: str | None
) -> None:
    """Fail before model parsing without retrying or mutating authentication."""
    client, session, response = _create_client(rate_limit_payload)
    if header is not None:
        response.headers["Retry-After"] = header
    original_auth = client._auth

    with patch("python_frank_energie.frank_energie.Invoices.from_dict") as parser:
        with pytest.raises(RateLimitException) as raised:
            await client.invoices("synthetic-site")

    assert isinstance(raised.value, RequestException)
    assert raised.value.operation_name == "Invoices"
    assert raised.value.retry_after == (120.0 if header == "120" else None)
    assert "Invoices" in str(raised.value)
    assert client._auth is original_auth
    parser.assert_not_called()
    session.post.assert_called_once()


@pytest.mark.parametrize("header", [None, "120", "not-a-date"])
@pytest.mark.asyncio
async def test_http_429_does_not_require_json(header: str | None) -> None:
    """Expose retry metadata from HTTP 429 even when its body is plain text."""
    client, session, response = _create_client({})
    response.json.side_effect = AssertionError("HTTP 429 body must not be parsed as JSON")
    headers = {"Retry-After": header} if header is not None else None
    http_error = aiohttp.ClientResponseError(
        request_info=MagicMock(), history=(), status=429, headers=headers
    )
    response.raise_for_status.side_effect = http_error

    with pytest.raises(RateLimitException) as raised:
        await client.invoices("synthetic-site")

    assert raised.value.operation_name == "Invoices"
    assert raised.value.retry_after == (120.0 if header == "120" else None)
    assert raised.value.__cause__ is http_error
    response.json.assert_not_awaited()
    session.post.assert_called_once()


@pytest.mark.parametrize("status", [HTTPStatus.OK, HTTPStatus.TOO_MANY_REQUESTS])
@pytest.mark.asyncio
async def test_invoices_preserves_asctime_retry_after(
    rate_limit_payload: dict[str, object], status: HTTPStatus
) -> None:
    """Expose the UTC delay from a legacy HTTP date through both error paths."""
    client, session, response = _create_client(rate_limit_payload)
    response.headers = {"Retry-After": "Wed Oct 28 14:00:00 2026"}
    if status == HTTPStatus.TOO_MANY_REQUESTS:
        response.raise_for_status.side_effect = aiohttp.ClientResponseError(
            request_info=MagicMock(), history=(), status=status, headers=response.headers
        )

    with patch("python_frank_energie.frank_energie.datetime") as clock:
        clock.now.return_value = datetime(2026, 10, 28, 12, tzinfo=UTC)
        with pytest.raises(RateLimitException) as raised:
            await client.invoices("synthetic-site")

    assert raised.value.operation_name == "Invoices"
    assert raised.value.retry_after == 7200.0
    session.post.assert_called_once()
    if status == HTTPStatus.TOO_MANY_REQUESTS:
        response.json.assert_not_awaited()
    else:
        response.json.assert_awaited_once()


@pytest.mark.parametrize(
    ("status", "exception_type"),
    [
        (HTTPStatus.UNAUTHORIZED, AuthRequiredException),
        (HTTPStatus.FORBIDDEN, AuthException),
        (HTTPStatus.BAD_REQUEST, RequestException),
        (HTTPStatus.INTERNAL_SERVER_ERROR, FrankEnergieException),
        (HTTPStatus.SERVICE_UNAVAILABLE, FrankEnergieException),
    ],
)
@pytest.mark.asyncio
async def test_other_http_errors_keep_existing_mapping(
    status: HTTPStatus, exception_type: type[FrankEnergieException]
) -> None:
    """Preserve established exception types for non-rate-limit HTTP errors."""
    client, session, response = _create_client({})
    response.raise_for_status.side_effect = aiohttp.ClientResponseError(
        request_info=MagicMock(), history=(), status=status
    )

    with pytest.raises(exception_type) as raised:
        await client.invoices("synthetic-site")

    assert type(raised.value) is exception_type
    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_partial_invoice_data_does_not_override_rate_limit(
    rate_limit_payload: dict[str, object],
) -> None:
    """Do not reinterpret a failed invoice response as successful partial data."""
    rate_limit_payload["data"] = {"invoices": {"allInvoices": []}}
    client, session, _ = _create_client(rate_limit_payload)

    with pytest.raises(RateLimitException):
        await client.invoices("synthetic-site")

    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_valid_empty_invoices_remain_valid() -> None:
    """Keep genuine empty invoice results distinct from rate-limited responses."""
    client, session, _ = _create_client({"data": {"invoices": {"allInvoices": []}}})
    result = await client.invoices("synthetic-site")

    assert result.all_periods_invoices == []
    assert result.total_costs_this_year == 0.0
    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_cancellation_is_not_retried() -> None:
    """Propagate cancellation without a retry or a domain-error conversion."""
    client, session, response = _create_client({})
    response.json.side_effect = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await client.invoices("synthetic-site")

    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_login_does_not_convert_rate_limit_to_auth_error(
    rate_limit_payload: dict[str, object],
) -> None:
    """Keep throttling distinguishable from incorrect login credentials."""
    client, session, _ = _create_client(rate_limit_payload)

    with pytest.raises(RateLimitException) as raised:
        await client.login("synthetic-user", "synthetic-password")  # noqa: S106

    assert raised.value.operation_name == "Login"
    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_month_summary_preserves_rate_limit_type(
    rate_limit_payload: dict[str, object],
) -> None:
    """Keep retry information when month-summary error handling rethrows."""
    client, session, _ = _create_client(rate_limit_payload)

    with pytest.raises(RateLimitException) as raised:
        await client.month_summary("synthetic-site")

    assert raised.value.operation_name == "MonthSummary"
    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_renewal_preserves_authentication_on_rate_limit(
    rate_limit_payload: dict[str, object],
) -> None:
    """Leave tokens intact when renewal encounters a transient rate limit."""
    client, session, _ = _create_client(rate_limit_payload)
    original_auth = client._auth

    with pytest.raises(RateLimitException) as raised:
        await client.renew_token()

    assert raised.value.operation_name == "RenewToken"
    assert client._auth is original_auth
    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_automatic_renewal_rate_limit_prevents_invoice_request(
    rate_limit_payload: dict[str, object],
) -> None:
    """Preserve expired authentication and send only the rate-limited renewal."""
    client, session, _ = _create_client(rate_limit_payload)
    original_auth = client._auth
    assert original_auth is not None
    original_auth.token_expires_at = datetime.now(UTC) - timedelta(minutes=10)

    with pytest.raises(RateLimitException) as raised:
        await client.invoices("synthetic-site")

    assert raised.value.operation_name == "RenewToken"
    assert client._auth is original_auth
    session.post.assert_called_once()
    assert session.post.call_args.kwargs["json"]["operationName"] == "RenewToken"


@pytest.mark.parametrize(
    ("first_message", "second_message", "exception_type"),
    [
        ("user-error:password-invalid", "Too Many Requests", AuthException),
        ("Too Many Requests", "user-error:password-invalid", RateLimitException),
        ("Graphql validation error", "Too Many Requests", FrankEnergieException),
        ("Too Many Requests", "Graphql validation error", RateLimitException),
        ("No reading dates found for user synthetic-user", "Too Many Requests", RateLimitException),
        ("Some unknown error message", "Too Many Requests", RateLimitException),
    ],
)
def test_graphql_errors_keep_response_order(
    first_message: str,
    second_message: str,
    exception_type: type[FrankEnergieException],
) -> None:
    """Keep the existing first recognized failure, without masking auth errors."""
    client = FrankEnergie()
    response = {"errors": [{"message": first_message}, {"message": second_message}]}

    with pytest.raises(exception_type) as raised:
        client._handle_errors(response, operation_name="Invoices", retry_after=120.0)

    assert type(raised.value) is exception_type
    if isinstance(raised.value, RateLimitException):
        assert raised.value.operation_name == "Invoices"
        assert raised.value.retry_after == 120.0


@pytest.mark.parametrize(
    ("message", "exception_type", "expected_message"),
    [
        (
            "user-error:refresh-token-invalid",
            RefreshTokenInvalidException,
            "Refresh token is invalid; reauthentication is required.",
        ),
        (
            "smart-battery-error:battery-not-found",
            SmartBatteryNotFoundException,
            "Smart battery not found for this user.",
        ),
    ],
)
def test_graphql_errors_preserve_specific_exception_types(
    message: str,
    exception_type: type[FrankEnergieException],
    expected_message: str,
) -> None:
    """Keep token and feature exceptions distinct after dispatch is refactored."""
    client = FrankEnergie()

    with pytest.raises(exception_type) as raised:
        client._handle_errors({"errors": [{"message": message}]})

    assert type(raised.value) is exception_type
    assert str(raised.value) == expected_message


def test_graphql_rate_limit_without_operation_name(
    rate_limit_payload: dict[str, object],
) -> None:
    """Recognize the reported message even when operation metadata is absent."""
    client = FrankEnergie()

    with pytest.raises(RateLimitException) as raised:
        client._handle_errors(rate_limit_payload)

    assert raised.value.retry_after is None


@pytest.mark.asyncio
async def test_successful_request_remains_unchanged() -> None:
    """Return successful GraphQL responses without scheduling extra requests."""
    payload = {"data": {"example": "value"}}
    client, session, _ = _create_client(payload)
    result = await client._query(FrankEnergieQuery("query Example { example }", "Example"))

    assert result == payload
    session.post.assert_called_once()
