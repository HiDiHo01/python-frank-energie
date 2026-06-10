"""Tests for contract price resolution change mutation method in FrankEnergie."""
# tests/test_contract_price_resolution_mutations.py

from __future__ import annotations

from datetime import date
from unittest.mock import AsyncMock, patch

import pytest

from python_frank_energie import ContractPriceResolutionChangeResult, FrankEnergie, Resolution
from python_frank_energie.exceptions import AuthRequiredException


def _make_api() -> FrankEnergie:
    """Return an authenticated FrankEnergie instance."""
    return FrankEnergie(auth_token="test-token", refresh_token="test-refresh")


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_success():
    api = _make_api()
    mock_response = {
        "data": {
            "contractPriceResolutionRequestChange": {
                "success": True,
                "reason": "Request accepted",
                "data": {
                    "effectiveDate": "2026-06-01",
                },
            }
        }
    }
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.contract_price_resolution_request_change("conn-123", "PT15M")

    assert isinstance(result, ContractPriceResolutionChangeResult)
    assert result.success is True
    assert result.reason == "Request accepted"
    assert result.effective_date == date(2026, 6, 1)


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_failure():
    api = _make_api()
    mock_response = {
        "data": {
            "contractPriceResolutionRequestChange": {
                "success": False,
                "reason": "Not allowed to switch at this time",
                "data": None,
            }
        }
    }
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)):
        result = await api.contract_price_resolution_request_change("conn-123", "PT60M")

    assert isinstance(result, ContractPriceResolutionChangeResult)
    assert result.success is False
    assert result.reason == "Not allowed to switch at this time"
    assert result.effective_date is None


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_raises_unauthenticated():
    api = FrankEnergie()
    with pytest.raises(AuthRequiredException):
        await api.contract_price_resolution_request_change("conn-123", "PT15M")


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_raises_value_error_missing_connection_id():
    api = _make_api()
    with pytest.raises(ValueError, match="connection_id must be provided"):
        await api.contract_price_resolution_request_change(None, "PT15M")


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_raises_value_error_missing_resolution():
    api = _make_api()
    with pytest.raises(ValueError, match="resolution must be provided"):
        await api.contract_price_resolution_request_change("conn-123", None)


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_sends_correct_variables_and_opname():
    api = _make_api()
    mock_response = {
        "data": {
            "contractPriceResolutionRequestChange": {
                "success": True,
                "reason": None,
                "data": None,
            }
        }
    }
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.contract_price_resolution_request_change("conn-123", "PT15M")

    called_query = mock_q.call_args[0][0]
    assert called_query.operation_name == "ContractPriceResolutionRequestChange"
    assert called_query.variables["connectionId"] == "conn-123"
    assert called_query.variables["resolution"] == "PT15M"
    assert "mutation ContractPriceResolutionRequestChange" in called_query.query
    assert "contractPriceResolutionRequestChange(" in called_query.query


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_returns_none_on_exception():
    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=Exception("API failure"))):
        result = await api.contract_price_resolution_request_change("conn-123", "PT15M")

    assert result is None


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_raises_cancelled_error():
    import asyncio

    api = _make_api()
    with patch.object(api, "_query", new=AsyncMock(side_effect=asyncio.CancelledError)):
        with pytest.raises(asyncio.CancelledError):
            await api.contract_price_resolution_request_change("conn-123", "PT15M")


def test_parse_date():
    from python_frank_energie.models import parse_date

    # None input
    assert parse_date(None) is None

    # Date object input
    d = date(2026, 6, 1)
    assert parse_date(d) == d

    # Valid ISO date string
    assert parse_date("2026-06-01") == date(2026, 6, 1)

    # ISO datetime string (with T)
    assert parse_date("2026-06-01T12:00:00Z") == date(2026, 6, 1)
    assert parse_date("2026-06-01T12:00:00+02:00") == date(2026, 6, 1)

    # Invalid input
    assert parse_date("invalid-date") is None


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_accepts_enum_directly():
    api = _make_api()
    mock_response = {
        "data": {
            "contractPriceResolutionRequestChange": {
                "success": True,
                "reason": None,
                "data": None,
            }
        }
    }
    with patch.object(api, "_query", new=AsyncMock(return_value=mock_response)) as mock_q:
        await api.contract_price_resolution_request_change("conn-123", Resolution.PT60M)

    called_query = mock_q.call_args[0][0]
    assert called_query.variables["resolution"] == "PT60M"


@pytest.mark.asyncio
async def test_contract_price_resolution_request_change_raises_value_error_invalid_resolution():
    api = _make_api()
    with pytest.raises(ValueError, match="resolution must be a valid Resolution enum"):
        await api.contract_price_resolution_request_change("conn-123", "PT30M")


def test_contract_price_resolution_change_result_from_dict_robustness():
    # Test valid parsing with boolean success
    res = ContractPriceResolutionChangeResult.from_dict(
        {"success": True, "reason": "OK", "data": {"effectiveDate": "2026-06-01"}}
    )
    assert res.success is True
    assert res.reason == "OK"
    assert res.effective_date == date(2026, 6, 1)

    # Test non-dict data payload (should not crash, effective_date should be None)
    res = ContractPriceResolutionChangeResult.from_dict({"success": True, "reason": "OK", "data": "not-a-dict"})
    assert res.success is True
    assert res.effective_date is None

    # Test string success truthiness ("true")
    res = ContractPriceResolutionChangeResult.from_dict({"success": "true", "reason": "OK", "data": None})
    assert res.success is True

    # Test string success truthiness ("1")
    res = ContractPriceResolutionChangeResult.from_dict({"success": "1", "reason": None, "data": None})
    assert res.success is True

    # Test string success falsiness ("false")
    res = ContractPriceResolutionChangeResult.from_dict({"success": "false", "reason": None, "data": None})
    assert res.success is False

    # Test invalid reason type
    res = ContractPriceResolutionChangeResult.from_dict({"success": True, "reason": 12345, "data": None})
    assert res.reason is None
