"""Regression tests for backend-reported GraphQL timeouts."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthRequiredException, FrankEnergieException, NetworkError
from python_frank_energie.frank_energie import FrankEnergieQuery

GRAPHQL_TIMEOUT_MESSAGE = "timeout of 60000ms exceeded"


def _make_client(payload: dict[str, object]) -> tuple[FrankEnergie, MagicMock, MagicMock]:
    """Build a client with a mocked HTTP 200 GraphQL response."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json = AsyncMock(return_value=payload)
    response.headers = {}

    session = MagicMock(spec=aiohttp.ClientSession)
    session.post.return_value.__aenter__.return_value = response

    client = FrankEnergie(session, auth_token="synthetic-token")  # noqa: S106
    return client, session, response


@pytest.mark.asyncio
async def test_usersites_graphql_timeout_is_network_error(caplog: pytest.LogCaptureFixture) -> None:
    """Classify the observed userSites timeout before parsing site data."""
    payload: dict[str, object] = {
        "data": None,
        "errors": [
            {
                "message": GRAPHQL_TIMEOUT_MESSAGE,
                "locations": [{"line": 2, "column": 3}],
                "path": ["userSites"],
                "extensions": {"privateReference": "synthetic-private-reference"},
            }
        ],
    }
    client, session, _ = _make_client(payload)

    with (
        caplog.at_level(logging.DEBUG, logger="python_frank_energie.frank_energie"),
        patch("python_frank_energie.frank_energie.UserSites.from_dict") as parser,
        pytest.raises(NetworkError, match=r"GraphQL timeout during operation \[UserSites\]"),
    ):
        await client.UserSites()

    parser.assert_not_called()
    session.post.assert_called_once()
    timeout_records = [
        record
        for record in caplog.records
        if record.getMessage() == "Frank Energie GraphQL timeout during operation [UserSites]"
    ]
    assert len(timeout_records) == 1
    assert timeout_records[0].levelno == logging.DEBUG
    assert "Unhandled GraphQL error" not in caplog.text
    assert "synthetic-private-reference" not in caplog.text
    assert "synthetic-token" not in caplog.text


@pytest.mark.parametrize("operation_name", ["UserSites", "Invoices", "MonthSummary"])
@pytest.mark.asyncio
async def test_graphql_timeout_is_not_tied_to_one_operation(operation_name: str) -> None:
    """Keep the shared query handler operation-independent for timeouts."""
    payload = {"data": None, "errors": [{"message": GRAPHQL_TIMEOUT_MESSAGE, "path": ["userSites"]}]}
    client, session, _ = _make_client(payload)
    query = FrankEnergieQuery(f"query {operation_name} {{ __typename }}", operation_name)

    with pytest.raises(NetworkError) as raised:
        await client._query(query)

    assert str(raised.value) == f"Frank Energie GraphQL timeout during operation [{operation_name}]"
    session.post.assert_called_once()


@pytest.mark.parametrize(
    "other_message",
    [
        "timeout of 60001ms exceeded",
        "timeout of 60000ms exceeded for an unknown reason",
        "unknown GraphQL error",
    ],
)
@pytest.mark.asyncio
async def test_unknown_graphql_errors_are_not_reclassified(other_message: str) -> None:
    """Match only the observed timeout message, not unrelated API errors."""
    payload = {"data": None, "errors": [{"message": other_message, "path": ["userSites"]}]}
    client, session, _ = _make_client(payload)

    result = await client._query(FrankEnergieQuery("query UserSites { __typename }", "UserSites"))

    assert result == payload
    session.post.assert_called_once()


@pytest.mark.parametrize(
    ("messages", "exception_type"),
    [
        (["user-error:auth-required", GRAPHQL_TIMEOUT_MESSAGE], AuthRequiredException),
        ([GRAPHQL_TIMEOUT_MESSAGE, "user-error:auth-required"], NetworkError),
    ],
)
def test_graphql_error_order_is_preserved(
    messages: list[str],
    exception_type: type[Exception],
) -> None:
    """Raise the first recognized error, preserving authentication precedence."""
    client = FrankEnergie()
    response = {"errors": [{"message": message} for message in messages]}

    with pytest.raises(exception_type) as raised:
        client._handle_errors(response, "UserSites")

    assert type(raised.value) is exception_type


@pytest.mark.parametrize(
    ("failure", "exception_type"),
    [
        (TimeoutError(), NetworkError),
        (asyncio.CancelledError(), asyncio.CancelledError),
    ],
)
@pytest.mark.asyncio
async def test_transport_timeout_and_cancellation_remain_unchanged(
    failure: BaseException,
    exception_type: type[BaseException],
) -> None:
    """Do not interfere with aiohttp timeout or task-cancellation handling."""
    client, session, response = _make_client({"data": {"version": "ok"}})
    response.json.side_effect = failure

    query = FrankEnergieQuery("query Example { version }", "Example")

    with pytest.raises(exception_type):
        await client._query(query)

    session.post.assert_called_once()


@pytest.mark.asyncio
async def test_month_summary_preserves_backend_network_error() -> None:
    """Propagate backend timeouts from the public month_summary method."""
    payload: dict[str, object] = {
        "data": None,
        "errors": [{"message": GRAPHQL_TIMEOUT_MESSAGE}],
    }
    client, session, _ = _make_client(payload)

    with pytest.raises(NetworkError, match=r"GraphQL timeout during operation \[MonthSummary\]"):
        await client.month_summary("synthetic-site-reference")

    session.post.assert_called_once()


@pytest.mark.parametrize(
    ("messages", "exception_type"),
    [
        (["unknown GraphQL error", GRAPHQL_TIMEOUT_MESSAGE], NetworkError),
        (["unknown GraphQL error", "user-error:auth-required", GRAPHQL_TIMEOUT_MESSAGE], AuthRequiredException),
    ],
)
def test_mixed_timeout_response_does_not_log_private_metadata(
    messages: list[str],
    exception_type: type[Exception],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Suppress unknown error details without changing recognized error precedence."""
    client = FrankEnergie()
    response = {
        "errors": [
            {
                "message": message,
                "extensions": {"privateReference": "synthetic-private-reference"},
            }
            for message in messages
        ]
    }

    with (
        caplog.at_level(logging.DEBUG, logger="python_frank_energie.frank_energie"),
        pytest.raises(exception_type),
    ):
        client._handle_errors(response, "UserSites")

    assert "synthetic-private-reference" not in caplog.text
    assert "Unhandled GraphQL error object" not in caplog.text


def test_validation_error_before_timeout_redacts_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Keep GraphQL validation details private when a backend timeout follows."""
    client = FrankEnergie()
    response = {
        "errors": [
            {
                "message": "Graphql validation error",
                "path": ["synthetic-private-reference"],
            },
            {"message": GRAPHQL_TIMEOUT_MESSAGE},
        ],
        "data": {"privateReference": "synthetic-private-reference"},
    }

    with (
        caplog.at_level(logging.DEBUG, logger="python_frank_energie.frank_energie"),
        pytest.raises(FrankEnergieException, match="Request failed: Graphql validation error"),
    ):
        client._handle_errors(response, "UserSites")

    assert "synthetic-private-reference" not in caplog.text
    assert "GraphQL validation error - query UserSites" in caplog.text
    assert "GraphQL timeout during operation" not in caplog.text
