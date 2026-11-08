"""Regression tests for partial responses to the Me operation."""

import json
import logging
from urllib.parse import urlsplit

import aiohttp
import pytest
from aresponses import ResponsesMockServer

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import (
    AuthRequiredException,
    FrankEnergieException,
    NetworkError,
    RateLimitException,
    RequestException,
)


def _add_me_response(aresponses: ResponsesMockServer, payload: dict[str, object]) -> None:
    """Mock an HTTP success containing a GraphQL execution result."""
    aresponses.add(
        urlsplit(FrankEnergie.DATA_URL).netloc,
        "/",
        "POST",
        aresponses.Response(
            text=json.dumps(payload),
            status=200,
            headers={"Content-Type": "application/json", "Retry-After": "42"},
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("hvac_data", "paths"),
    [
        pytest.param(None, (["userSmartHvac"],), id="null-hvac"),
        pytest.param(
            {"isActivated": True},
            (["userSmartHvac", "hasAcceptedTerms"], ["userSmartHvac", "isAvailableOnSite"]),
            id="partial-hvac",
        ),
    ],
)
async def test_me_keeps_user_data_when_only_hvac_fails(
    aresponses: ResponsesMockServer,
    caplog: pytest.LogCaptureFixture,
    hvac_data: dict[str, object] | None,
    paths: tuple[list[str], ...],
) -> None:
    """Keep the valid user data and discard the failed HVAC subtree."""
    _add_me_response(
        aresponses,
        {
            "data": {"me": {"id": "synthetic-user"}, "userSmartHvac": hvac_data},
            "errors": [
                {
                    "message": "synthetic-private-hvac-error",
                    "path": path,
                    "extensions": {"privateReference": "synthetic-private-hvac-reference"},
                }
                for path in paths
            ],
        },
    )

    async with aiohttp.ClientSession() as session:
        client = FrankEnergie(session, auth_token="synthetic-token")  # noqa: S106
        with caplog.at_level(logging.DEBUG, logger="python_frank_energie.frank_energie"):
            result = await client.me("synthetic-site")

    assert result.id == "synthetic-user"
    assert result.user_smart_hvac is None
    assert any(
        record.levelno == logging.WARNING and "Returning partial Me data" in record.getMessage()
        for record in caplog.records
    )
    assert "synthetic-private-hvac-error" not in caplog.text
    assert "synthetic-private-hvac-reference" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("me_data", "errors"),
    [
        pytest.param(
            {"id": "synthetic-user"},
            [{"message": "Required user data failed", "path": ["me", "id"]}],
            id="required-field",
        ),
        pytest.param(
            {"id": "synthetic-user"},
            [{"message": "Unscoped GraphQL error"}],
            id="unscoped-error",
        ),
        pytest.param(
            {"id": "synthetic-user"},
            [{"message": "Invalid path", "path": "userSmartHvac"}],
            id="malformed-path",
        ),
        pytest.param(
            {"id": "synthetic-user"},
            [
                {"message": "HVAC failed", "path": ["userSmartHvac"]},
                {"message": "User data failed", "path": ["me"]},
            ],
            id="mixed-errors",
        ),
        pytest.param(
            None,
            [{"message": "HVAC failed", "path": ["userSmartHvac"]}],
            id="missing-me",
        ),
        pytest.param(
            {"countryCode": "NL"},
            [{"message": "HVAC failed", "path": ["userSmartHvac"]}],
            id="missing-user-id",
        ),
        pytest.param(
            {"id": 123},
            [{"message": "HVAC failed", "path": ["userSmartHvac"]}],
            id="invalid-user-id",
        ),
    ],
)
async def test_me_preserves_other_graphql_failures(
    aresponses: ResponsesMockServer,
    me_data: dict[str, object] | None,
    errors: list[dict[str, object]],
) -> None:
    """Require usable user data and errors exclusively under the HVAC root."""
    _add_me_response(aresponses, {"data": {"me": me_data, "userSmartHvac": None}, "errors": errors})

    async with aiohttp.ClientSession() as session:
        client = FrankEnergie(session, auth_token="synthetic-token")  # noqa: S106
        with pytest.raises(RequestException):
            await client.me("synthetic-site")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "exception_type"),
    [
        ("user-error:auth-required", AuthRequiredException),
        ("Too Many Requests", RateLimitException),
        ("timeout of 60000ms exceeded", NetworkError),
        ("Graphql validation error", FrankEnergieException),
    ],
)
async def test_me_preserves_recognized_errors_even_with_hvac_path(
    aresponses: ResponsesMockServer,
    message: str,
    exception_type: type[FrankEnergieException],
) -> None:
    """Classify known request failures before considering partial recovery."""
    _add_me_response(
        aresponses,
        {
            "data": {"me": {"id": "synthetic-user"}, "userSmartHvac": None},
            "errors": [{"message": message, "path": ["userSmartHvac"]}],
        },
    )

    async with aiohttp.ClientSession() as session:
        client = FrankEnergie(session, auth_token="synthetic-token")  # noqa: S106
        with pytest.raises(exception_type) as error:
            await client.me("synthetic-site")

    assert type(error.value) is exception_type
    if isinstance(error.value, RateLimitException):
        assert error.value.retry_after == pytest.approx(42.0)
