"""Regression tests for nested UserSites address parsing and validation."""

import logging
from unittest.mock import AsyncMock, patch

import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.models import Address, DeliverySite, UserSites


def _site(reference: str, address: object) -> dict[str, object]:
    """Build a fictional delivery site without personal account information."""
    return {
        "reference": reference,
        "segments": ["ELECTRICITY"],
        "status": "IN_DELIVERY",
        "propositionType": "DYNAMIC",
        "addressHasMultipleSites": False,
        "deliveryStartDate": "2026-11-01",
        "deliveryEndDate": None,
        "firstMeterReadingDate": "2026-11-01",
        "lastMeterReadingDate": "2026-11-21",
        "address": address,
    }


def _response(*sites: dict[str, object]) -> dict[str, object]:
    """Wrap synthetic delivery sites in the actual UserSites response shape."""
    return {"data": {"userSites": list(sites)}}


def test_user_sites_parses_nested_lines_and_distinct_site_addresses() -> None:
    """Preserve the first-site summary and separately parsed addresses for every site."""
    first_lines = ["Example Road 12", "1234 AB Exampletown"]
    second_lines = ["Another Road 7A", "1000 Brussels"]
    result = UserSites.from_dict(
        _response(
            _site("synthetic-site-1", {"addressFormatted": first_lines}),
            _site("synthetic-site-2", {"addressFormatted": second_lines}),
        )
    )

    assert result.addressFormatted == first_lines
    assert isinstance(result.addressFormatted, list)
    assert result.addressFormatted is not first_lines
    assert result.reference == "synthetic-site-1"
    assert result.lastMeterReadingDate == "2026-11-21"
    assert result.segments == ["ELECTRICITY"]
    assert len(result.deliverySites) == 2

    first_site, second_site = result.deliverySites
    assert isinstance(first_site, DeliverySite)
    assert isinstance(second_site, DeliverySite)
    assert first_site.address is not None
    assert first_site.address.street == "Example Road"
    assert first_site.address.houseNumber == "12"
    assert second_site.reference == "synthetic-site-2"
    assert second_site.address is not None
    assert second_site.address.street == "Another Road"
    assert second_site.address.houseNumber == "7"
    assert second_site.address.houseNumberAddition == "A"
    assert second_site.address.zipCode == "1000"
    assert second_site.address.city == "Brussels"
    assert result.format_delivery_site_as_dict == [
        "Example Road 12 1234 AB Exampletown",
        "Another Road 7 A 1000 Brussels",
    ]


@pytest.mark.parametrize(
    "formatted_lines",
    [
        None,
        "",
        "Example Road 12",
        [],
        ["Example Road 12"],
        ["Example Road 12", None],
        [None, "1234 AB Exampletown"],
        ["Example Road 12", 1234],
        ["Example Road 12", True],
        ["", "1234 AB Exampletown"],
        ["Example Road 12", "  "],
        ["Example Road 12", "1234 AB Exampletown", None],
    ],
)
def test_address_rejects_missing_or_malformed_formatted_lines(formatted_lines: object) -> None:
    """Reject invalid address lists rather than stringifying arbitrary elements."""
    assert Address.from_dict({"addressFormatted": formatted_lines}) is None


def test_address_parses_first_two_of_multiple_valid_lines() -> None:
    """Keep additional valid lines in the raw list without changing legacy address parsing."""
    lines = ["Example Road 12", "1234 AB Exampletown", "Third line"]
    result = UserSites.from_dict(_response(_site("synthetic-site", {"addressFormatted": lines})))

    assert result.addressFormatted == lines
    assert isinstance(result.deliverySites[0], DeliverySite)
    assert result.deliverySites[0].address is not None
    assert result.deliverySites[0].address.city == "Exampletown"


@pytest.mark.parametrize(
    "address_payload",
    [
        None,
        "not-an-object",
        {},
        {"addressFormatted": None},
        {"addressFormatted": []},
        {"addressFormatted": ["Example Road 12"]},
        {"addressFormatted": ["Example Road 12", None]},
        {"addressFormatted": ["Example Road 12", "  "]},
    ],
)
def test_user_sites_invalid_nested_address_returns_none(address_payload: object) -> None:
    """Keep invalid nested address values unavailable in both model representations."""
    parsed = UserSites.from_dict(_response(_site("synthetic-site", address_payload)))

    assert parsed.addressFormatted is None
    assert len(parsed.deliverySites) == 1
    assert isinstance(parsed.deliverySites[0], DeliverySite)
    assert parsed.deliverySites[0].address is None
    assert parsed.format_delivery_site_as_dict == []


def test_user_sites_missing_address_returns_none() -> None:
    """Missing nested address is distinct from a valid formatted address."""
    site = _site("synthetic-site", None)
    del site["address"]
    parsed = UserSites.from_dict(_response(site))

    assert parsed.addressFormatted is None
    assert isinstance(parsed.deliverySites[0], DeliverySite)
    assert parsed.deliverySites[0].address is None


def test_user_sites_does_not_log_full_provider_addresses(caplog: pytest.LogCaptureFixture) -> None:
    """Do not expose site identifiers or formatted addresses at DEBUG level."""
    private_site = "synthetic-private-reference"
    private_street = "Synthetic Private Street 12"
    with caplog.at_level(logging.DEBUG, logger="python_frank_energie.models"):
        UserSites.from_dict(_response(_site(private_site, {"addressFormatted": [private_street, "1234 AB Town"]})))
        Address.from_dict({"addressFormatted": [private_street, None]})

    assert private_site not in caplog.text
    assert private_street not in caplog.text


@pytest.mark.asyncio
async def test_public_user_sites_method_returns_corrected_model() -> None:
    """Verify the public alias still fetches the existing query and parses nested addresses."""
    client = FrankEnergie(auth_token="synthetic-auth-token")
    address_lines = ["Example Road 12", "1234 AB Exampletown"]

    with patch.object(
        client,
        "_query",
        new_callable=AsyncMock,
        return_value=_response(_site("synthetic-site", {"addressFormatted": address_lines})),
    ) as mocked_query:
        parsed = await client.user_sites()

    assert parsed.addressFormatted == address_lines
    mocked_query.assert_awaited_once()
    actual_query = mocked_query.await_args.args[0]
    assert actual_query.operation_name == "UserSites"
    assert actual_query.variables == {}
    assert "addressFormatted" in actual_query.query
