"""Regression tests for the backward-compatible snake_case UserSites alias."""

from unittest.mock import AsyncMock, patch

import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthRequiredException, RequestException


@pytest.mark.asyncio
@pytest.mark.parametrize("site_reference", (None, "synthetic-site-reference"))
async def test_user_sites_alias_forwards_argument_and_result(site_reference: str | None) -> None:
    """Forward optional site references and return the original result object."""
    client = FrankEnergie()
    expected_sites = object()

    with patch.object(client, "UserSites", new_callable=AsyncMock, return_value=expected_sites) as legacy_method:
        result = await client.user_sites(site_reference)

    assert result is expected_sites
    legacy_method.assert_awaited_once_with(site_reference)


@pytest.mark.asyncio
async def test_user_sites_alias_uses_legacy_default() -> None:
    """Preserve the no-argument call through the legacy implementation."""
    client = FrankEnergie()
    expected_sites = object()

    with patch.object(client, "UserSites", new_callable=AsyncMock, return_value=expected_sites) as legacy_method:
        result = await client.user_sites()

    assert result is expected_sites
    legacy_method.assert_awaited_once_with(None)


@pytest.mark.asyncio
async def test_user_sites_alias_propagates_request_errors() -> None:
    """Preserve the original exception object instead of masking errors."""
    client = FrankEnergie()
    expected_error = RequestException("Synthetic request failure")

    with patch.object(client, "UserSites", new_callable=AsyncMock, side_effect=expected_error) as legacy_method:
        with pytest.raises(RequestException) as error_info:
            await client.user_sites("synthetic-site-reference")

    assert error_info.value is expected_error
    legacy_method.assert_awaited_once_with("synthetic-site-reference")


@pytest.mark.asyncio
async def test_user_sites_alias_preserves_authentication_requirement() -> None:
    """Raise the existing authentication error on an unauthenticated client."""
    client = FrankEnergie()

    with pytest.raises(AuthRequiredException):
        await client.user_sites()
