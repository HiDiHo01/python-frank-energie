"""Regression tests for nested UserSites address parsing and validation."""

import logging
from unittest.mock import AsyncMock, patch

import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.models import Address, DeliverySite, UserSites

MODELS_LOGGER = "python_frank_energie.models"
MALFORMED_ADDRESS_WARNING = (
    MODELS_LOGGER,
    logging.WARNING,
    "Ignoring malformed delivery site address (expected at least two nonempty formatted lines)",
)


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


def test_user_sites_parses_nested_lines_and_distinct_site_addresses(caplog: pytest.LogCaptureFixture) -> None:
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
    assert caplog.record_tuples == []


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
        "not-an-object",
        {},
        {"addressFormatted": None},
        {"addressFormatted": []},
        {"addressFormatted": ["Example Road 12"]},
        {"addressFormatted": ["Example Road 12", None]},
        {"addressFormatted": ["Example Road 12", "  "]},
    ],
)
def test_user_sites_invalid_nested_address_returns_none(
    address_payload: object, caplog: pytest.LogCaptureFixture
) -> None:
    """Warn once for a malformed first-site address and leave both representations unavailable."""
    with caplog.at_level(logging.DEBUG, logger=MODELS_LOGGER):
        parsed = UserSites.from_dict(_response(_site("synthetic-site", address_payload)))

    assert parsed.addressFormatted is None
    assert len(parsed.deliverySites) == 1
    assert isinstance(parsed.deliverySites[0], DeliverySite)
    assert parsed.deliverySites[0].address is None
    assert parsed.format_delivery_site_as_dict == []
    assert caplog.record_tuples == [MALFORMED_ADDRESS_WARNING]


@pytest.mark.parametrize("omit_address", [True, False], ids=["missing", "null"])
def test_user_sites_missing_address_returns_none(omit_address: bool, caplog: pytest.LogCaptureFixture) -> None:
    """Keep missing and explicit null addresses unavailable without logging them."""
    site = _site("synthetic-site", None)
    if omit_address:
        del site["address"]
    with caplog.at_level(logging.DEBUG, logger=MODELS_LOGGER):
        parsed = UserSites.from_dict(_response(site))

    assert parsed.addressFormatted is None
    assert isinstance(parsed.deliverySites[0], DeliverySite)
    assert parsed.deliverySites[0].address is None
    assert caplog.record_tuples == []


def test_delivery_site_warns_on_malformed_address(caplog: pytest.LogCaptureFixture) -> None:
    """Report a malformed address when a single delivery site is parsed directly."""
    parsed = DeliverySite.from_dict(_site("synthetic-site", {"addressFormatted": []}))

    assert parsed is not None
    assert parsed.address is None
    assert caplog.record_tuples == [MALFORMED_ADDRESS_WARNING]


def test_user_sites_does_not_log_full_provider_addresses(caplog: pytest.LogCaptureFixture) -> None:
    """Warn once per malformed site and keep valid addresses and site identifiers out of all messages."""
    private_street = "Synthetic Private Street 12"
    malformed = {"addressFormatted": [private_street, None]}
    valid_site = _site("synthetic-valid", {"addressFormatted": [private_street, "1234 AB Town"]})
    with caplog.at_level(logging.DEBUG, logger=MODELS_LOGGER):
        UserSites.from_dict(
            _response(
                valid_site,
                _site("synthetic-private-reference-1", malformed),
                _site("synthetic-private-reference-2", malformed),
            )
        )

    assert caplog.record_tuples == [MALFORMED_ADDRESS_WARNING, MALFORMED_ADDRESS_WARNING]


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
