"""Regression tests for the five read-only operations from historical GraphQL comments."""

from __future__ import annotations

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import (
    AuthRequiredException,
    FrankEnergieException,
    NetworkError,
    RateLimitException,
    RequestException,
)
from python_frank_energie.frank_energie import FrankEnergieQuery

# Synthetic reproduction of observed read-only API response shapes.
_SMART_CHARGING = {
    "isActivated": False,
    "provider": "ENODE",
    "userCreatedAt": None,
    "userId": None,
    "isAvailableInCountry": True,
    "needsSubscription": False,
    "subscription": None,
}
_ACTIVE_SMART_CHARGING = {
    "isActivated": True,
    "provider": "ENODE",
    "userCreatedAt": "2026-01-15T12:34:56.789Z",
    "userId": "synthetic-smart-charging-user",
    "isAvailableInCountry": True,
    "needsSubscription": False,
    "subscription": None,
}
# Synthetic-only populated subscription; non-null provider responses remain unverified.
_POPULATED_SMART_CHARGING_SUBSCRIPTION = {
    "startDate": "2026-01-01T00:00:00Z",
    "endDate": None,
    "id": "synthetic-subscription",
    "proposition": {"product": "SYNTHETIC", "countryCode": "NL"},
}
_APP_VERSION = {"ios": None, "android": None}
_CERTIFICATE = {
    "id": "synthetic-certificate",
    "imageUrl": None,
    "imagePath": None,
    "createdAt": None,
    "treesAmount": 1,
}
_NOTICE = {"active": True, "message": "Synthetic provider notice for testing.", "title": ""}
_REWARDS = {
    "me": {"id": "synthetic-user", "UserSettings": {"id": "synthetic-settings", "rewardPayoutPreference": "DISCOUNT"}},
    "userRewardsData": {
        "activeConnectionsCount": 1,
        "activeFriendsCount": 0,
        "acceptedRewards": [],
        "upcomingRewards": [],
    },
}
# Synthetic reproduction of a populated reward, without observed account IDs or referrer details.
_POPULATED_REWARDS = {
    "me": {
        "id": "synthetic-account-2",
        "UserSettings": {"id": "synthetic-settings-2", "rewardPayoutPreference": "DISCOUNT"},
    },
    "userRewardsData": {
        "activeConnectionsCount": 1,
        "activeFriendsCount": 1,
        "acceptedRewards": [
            {
                "id": "synthetic-reward-1",
                "awardedDiscount": 100,
                "awardedTreesAmount": None,
                "availableForAcceptanceOn": "2026-01-01T00:00:00.000Z",
                "treesAmountPerConnection": 0,
                "discountPerConnection": 100,
                "acceptedOn": "2026-02-01T00:00:00.000Z",
                "isRewardForOwnSignup": True,
                "hasPossibleSmartChargingBonus": False,
                "coolingDownPeriod": 12,
                "InviteLink": {
                    "id": "synthetic-invitation-1",
                    "type": "GROUP",
                    "fromName": "synthetic-referrer.example.invalid",
                    "templateType": "DEFAULT",
                    "awardRewardType": "ONE_TIME_AFTER_ONE_YEAR_PRO_RATA_IF_LEAVING_EARLIER",
                    "treesAmountPerConnection": 0,
                    "discountPerConnection": 35,
                },
                "AdditionalBonuses": [],
            }
        ],
        "upcomingRewards": [],
    },
}

_CASES = (
    ("user_smart_charging", "UserSmartCharging", "userSmartCharging", _SMART_CHARGING),
    ("app_version", "AppVersion", "appVersion", _APP_VERSION),
    ("tree_certificates", "TreeCertificates", "treeCertificates", [_CERTIFICATE]),
    ("app_notice", "AppNotice", "appNotice", _NOTICE),
)


@pytest.mark.asyncio
@pytest.mark.parametrize(("method_name", "operation_name", "root_name", "record"), _CASES)
async def test_extra_query_request_and_result(
    method_name: str, operation_name: str, root_name: str, record: object
) -> None:
    """Use the named GraphQL operation with no variables and preserve its returned record."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(client, "_query", new_callable=AsyncMock, return_value={"data": {root_name: record}}) as request:
        result = await getattr(client, method_name)()

    sent_query = request.await_args.args[0]
    assert isinstance(sent_query, FrankEnergieQuery)
    assert sent_query.operation_name == operation_name
    assert sent_query.variables == {}
    assert f"query {operation_name} " in sent_query.query
    assert root_name in sent_query.query
    assert result == record
    if isinstance(record, dict):
        assert result is record
    elif isinstance(record, list):
        assert isinstance(result, list)
        assert result[0] is record[0]


@pytest.mark.asyncio
async def test_user_smart_charging_preserves_active_status_and_timestamp() -> None:
    """Preserve the observed active status, opaque user ID, timestamp, and null subscription."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(
        client,
        "_query",
        new_callable=AsyncMock,
        return_value={"data": {"userSmartCharging": _ACTIVE_SMART_CHARGING}},
    ) as request:
        result = await client.user_smart_charging()

    sent_query = request.await_args.args[0]
    assert isinstance(sent_query, FrankEnergieQuery)
    assert sent_query.operation_name == "UserSmartCharging"
    assert sent_query.variables == {}
    assert result == _ACTIVE_SMART_CHARGING
    assert result["isActivated"] is True
    assert result["userCreatedAt"] == "2026-01-15T12:34:56.789Z"
    assert result["userId"] == "synthetic-smart-charging-user"
    assert result["isAvailableInCountry"] is True
    assert result["needsSubscription"] is False
    assert result["subscription"] is None


@pytest.mark.asyncio
async def test_user_smart_charging_preserves_populated_subscription() -> None:
    """Keep a complete synthetic nested subscription and its values unchanged."""
    status = {**_SMART_CHARGING, "subscription": _POPULATED_SMART_CHARGING_SUBSCRIPTION}
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(
        client, "_query", new_callable=AsyncMock, return_value={"data": {"userSmartCharging": status}}
    ):
        result = await client.user_smart_charging()

    assert result is status
    assert result["subscription"] is _POPULATED_SMART_CHARGING_SUBSCRIPTION
    assert isinstance(result["subscription"], dict)
    assert result["subscription"]["endDate"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_field", ("startDate", "endDate", "id", "proposition"))
async def test_user_smart_charging_rejects_missing_subscription_fields(missing_field: str) -> None:
    """Require all fields selected from a non-null Smart Charging subscription."""
    subscription = {
        key: value for key, value in _POPULATED_SMART_CHARGING_SUBSCRIPTION.items() if key != missing_field
    }
    status = {**_SMART_CHARGING, "subscription": subscription}
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(
            client, "_query", new_callable=AsyncMock, return_value={"data": {"userSmartCharging": status}}
        ),
        pytest.raises(RequestException, match=r"Invalid userSmartCharging\\.subscription response"),
    ):
        await client.user_smart_charging()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_subscription",
    (
        "invalid",
        [1],
        {**_POPULATED_SMART_CHARGING_SUBSCRIPTION, "proposition": None},
        {**_POPULATED_SMART_CHARGING_SUBSCRIPTION, "proposition": []},
        {**_POPULATED_SMART_CHARGING_SUBSCRIPTION, "proposition": {"product": "SYNTHETIC"}},
        {**_POPULATED_SMART_CHARGING_SUBSCRIPTION, "proposition": {"countryCode": "NL"}},
    ),
)
async def test_user_smart_charging_rejects_malformed_subscription(invalid_subscription: object) -> None:
    """Reject malformed subscription and proposition shapes with RequestException."""
    status = {**_SMART_CHARGING, "subscription": invalid_subscription}
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(
            client, "_query", new_callable=AsyncMock, return_value={"data": {"userSmartCharging": status}}
        ),
        pytest.raises(RequestException, match=r"Invalid userSmartCharging\\.subscription"),
    ):
        await client.user_smart_charging()


@pytest.mark.asyncio
async def test_app_version_preserves_nullable_platforms() -> None:
    """An observed successful response may have null Android and iOS details."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(
        client, "_query", new_callable=AsyncMock, return_value={"data": {"appVersion": {"ios": None, "android": None}}}
    ):
        result = await client.app_version()
    assert result == {"ios": None, "android": None}


@pytest.mark.asyncio
async def test_app_notice_preserves_active_message_and_empty_title() -> None:
    """Preserve the live-observed active notice shape, including an empty title."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(
        client,
        "_query",
        new_callable=AsyncMock,
        return_value={"data": {"appNotice": _NOTICE}},
    ) as request:
        result = await client.app_notice()

    sent_query = request.await_args.args[0]
    assert isinstance(sent_query, FrankEnergieQuery)
    assert sent_query.operation_name == "AppNotice"
    assert sent_query.variables == {}
    assert "appNotice {" in sent_query.query
    assert result == _NOTICE
    assert result["active"] is True
    assert result["title"] == ""
    assert result["message"] == "Synthetic provider notice for testing."


@pytest.mark.asyncio
async def test_user_rewards_query_preserves_both_roots_and_fragment() -> None:
    """Request the original rewards fragment and return both independently nullable roots."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(client, "_query", new_callable=AsyncMock, return_value={"data": _REWARDS}) as request:
        result = await client.user_rewards_data()

    sent_query = request.await_args.args[0]
    assert isinstance(sent_query, FrankEnergieQuery)
    assert sent_query.operation_name == "UserRewardsData"
    assert sent_query.variables == {}
    assert "fragment UserRewardV2Fields on UserRewardV2" in sent_query.query
    assert "AdditionalBonuses" in sent_query.query
    assert result == _REWARDS
    assert result["me"] is _REWARDS["me"]
    assert result["userRewardsData"] is _REWARDS["userRewardsData"]


@pytest.mark.asyncio
async def test_user_rewards_preserves_populated_accepted_reward() -> None:
    """Preserve the observed nested reward record without converting dates or nullable fields."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(
        client,
        "_query",
        new_callable=AsyncMock,
        return_value={"data": _POPULATED_REWARDS},
    ) as request:
        result = await client.user_rewards_data()

    sent_query = request.await_args.args[0]
    assert isinstance(sent_query, FrankEnergieQuery)
    assert sent_query.operation_name == "UserRewardsData"
    assert "fragment UserRewardV2Fields on UserRewardV2" in sent_query.query
    assert "InviteLink {" in sent_query.query
    assert "AdditionalBonuses {" in sent_query.query
    assert result == _POPULATED_REWARDS

    reward = result["userRewardsData"]["acceptedRewards"][0]
    assert reward["awardedTreesAmount"] is None
    assert reward["isRewardForOwnSignup"] is True
    assert reward["hasPossibleSmartChargingBonus"] is False
    assert reward["availableForAcceptanceOn"] == "2026-01-01T00:00:00.000Z"
    assert reward["acceptedOn"] == "2026-02-01T00:00:00.000Z"
    assert reward["InviteLink"]["type"] == "GROUP"
    assert reward["AdditionalBonuses"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("method_name", "operation_name", "root_name", "record"), _CASES)
async def test_extra_query_explicit_null_is_not_missing(
    method_name: str, operation_name: str, root_name: str, record: object
) -> None:
    """Accept explicit null but never infer it from a missing root."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(client, "_query", new_callable=AsyncMock, return_value={"data": {root_name: None}}):
        assert await getattr(client, method_name)() is None


@pytest.mark.asyncio
async def test_empty_certificates_are_not_an_error() -> None:
    """Preserve the observed successful empty list and verify the named operation."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(
        client,
        "_query",
        new_callable=AsyncMock,
        return_value={"data": {"treeCertificates": []}},
    ) as request:
        result = await client.tree_certificates()

    sent_query = request.await_args.args[0]
    assert isinstance(sent_query, FrankEnergieQuery)
    assert sent_query.operation_name == "TreeCertificates"
    assert sent_query.variables == {}
    assert "treeCertificates {" in sent_query.query
    assert result == []


@pytest.mark.asyncio
async def test_rewards_null_roots_remain_distinct() -> None:
    """Keep nullable reward and account data unchanged."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(
        client,
        "_query",
        new_callable=AsyncMock,
        return_value={"data": {"me": None, "userRewardsData": _REWARDS["userRewardsData"]}},
    ):
        result = await client.user_rewards_data()
    assert result == {"me": None, "userRewardsData": _REWARDS["userRewardsData"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("method_name", (*[case[0] for case in _CASES], "user_rewards_data"))
async def test_extra_operations_require_authentication(method_name: str) -> None:
    """Reject unauthenticated calls before any network request is attempted."""
    client = FrankEnergie()
    with (
        patch.object(client, "_query", new_callable=AsyncMock) as request,
        pytest.raises(AuthRequiredException, match="Authentication is required"),
    ):
        await getattr(client, method_name)()
    request.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    (
        {},
        {"data": None},
        {"data": []},
        {"data": {}},
        {"data": {"appVersion": []}},
        {"data": {"appVersion": {"ios": {}}}},
        {"data": {"appVersion": _APP_VERSION}, "errors": None},
        {"data": {"appVersion": _APP_VERSION}, "errors": "invalid"},
        {"data": {"appVersion": _APP_VERSION}, "errors": [{"message": "synthetic-error"}]},
    ),
)
async def test_app_version_rejects_invalid_responses(response: dict[str, object]) -> None:
    """Reject missing, malformed, or failed GraphQL payloads rather than reporting success."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, return_value=response),
        pytest.raises(RequestException),
    ):
        await client.app_version()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    (
        {"data": {"treeCertificates": {}}},
        {"data": {"treeCertificates": [None]}},
        {"data": {"treeCertificates": [{"id": "synthetic"}]}},
        {"data": {"treeCertificates": [_CERTIFICATE, 12]}},
    ),
)
async def test_tree_certificates_rejects_incomplete_inventory(response: dict[str, object]) -> None:
    """Reject the entire inventory rather than silently removing invalid records."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, return_value=response),
        pytest.raises(RequestException),
    ):
        await client.tree_certificates()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    (
        {"data": {"me": _REWARDS["me"]}},
        {"data": {"me": _REWARDS["me"], "userRewardsData": []}},
        {"data": {"me": _REWARDS["me"], "userRewardsData": {"activeFriendsCount": 0}}},
    ),
)
async def test_rewards_rejects_missing_or_malformed_response(response: dict[str, object]) -> None:
    """Require both expected roots and the selected reward summary fields."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, return_value=response),
        pytest.raises(RequestException),
    ):
        await client.user_rewards_data()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    (
        (RateLimitException("UserSmartCharging", retry_after=120), RateLimitException),
        (NetworkError("synthetic network error"), NetworkError),
        (asyncio.CancelledError(), asyncio.CancelledError),
    ),
)
async def test_extra_query_propagates_transport_errors(error: BaseException, expected: type[BaseException]) -> None:
    """Preserve rate-limit metadata, network failures, and cancellation."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, side_effect=error),
        pytest.raises(expected) as raised,
    ):
        await client.user_smart_charging()
    assert raised.value is error


@pytest.mark.asyncio
@pytest.mark.parametrize("operation_name", (*[case[1] for case in _CASES], "UserRewardsData"))
async def test_extra_query_generic_client_error_redacts_sensitive_details(
    operation_name: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Do not leak a generic HTTP client exception for the new read-only operations."""
    private_message = "synthetic-private-client-error"
    session = MagicMock(spec=aiohttp.ClientSession)
    session.post.side_effect = aiohttp.ClientError(private_message)
    client = FrankEnergie(session)
    query = FrankEnergieQuery(f"query {operation_name} {{ __typename }}", operation_name)

    with (
        caplog.at_level(logging.DEBUG, logger="python_frank_energie.frank_energie"),
        pytest.raises(NetworkError) as raised,
    ):
        await client._query(query)

    assert str(raised.value) == "Frank Energie HTTP client error"
    assert raised.value.__cause__ is None
    assert private_message not in str(raised.value)
    assert private_message not in caplog.text
    assert f"Frank Energie HTTP client error during [{operation_name}]" in caplog.text
    session.post.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "platform_data",
    ({"ios": {}, "android": None}, {"ios": {"version": []}, "android": None}, {"ios": None, "android": 12}),
)
async def test_app_version_rejects_malformed_nested_platforms(platform_data: dict[str, object]) -> None:
    """Reject malformed nested platform records and selected versions."""
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, return_value={"data": {"appVersion": platform_data}}),
        pytest.raises(RequestException),
    ):
        await client.app_version()


@pytest.mark.asyncio
async def test_app_version_preserves_populated_platform_version() -> None:
    """Return valid platform details unchanged."""
    platforms = {"ios": {"version": "1.2.3"}, "android": None}
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(client, "_query", new_callable=AsyncMock, return_value={"data": {"appVersion": platforms}}):
        result = await client.app_version()
    assert result is platforms


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("acceptedRewards", "invalid"),
        ("acceptedRewards", 12),
        ("upcomingRewards", {}),
    ),
)
async def test_rewards_rejects_invalid_collection_types(field_name: str, invalid_value: object) -> None:
    """Reject non-null reward collections that are not lists."""
    rewards = {**_REWARDS["userRewardsData"], field_name: invalid_value}
    response = {"data": {"me": _REWARDS["me"], "userRewardsData": rewards}}
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, return_value=response),
        pytest.raises(RequestException, match=field_name),
    ):
        await client.user_rewards_data()


@pytest.mark.asyncio
async def test_rewards_preserves_nullable_collections() -> None:
    """Accept explicitly null collection fields as supplied by the provider."""
    rewards = {**_REWARDS["userRewardsData"], "acceptedRewards": None, "upcomingRewards": None}
    response = {"data": {"me": _REWARDS["me"], "userRewardsData": rewards}}
    client = FrankEnergie(auth_token="synthetic-access-token")
    with patch.object(client, "_query", new_callable=AsyncMock, return_value=response):
        result = await client.user_rewards_data()
    assert result["userRewardsData"] is rewards


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_record",
    (
        {"id": "synthetic-reward-only"},
        {**_POPULATED_REWARDS["userRewardsData"]["acceptedRewards"][0], "InviteLink": {}},
        {**_POPULATED_REWARDS["userRewardsData"]["acceptedRewards"][0], "AdditionalBonuses": "invalid"},
        {**_POPULATED_REWARDS["userRewardsData"]["acceptedRewards"][0], "AdditionalBonuses": [{}]},
    ),
)
async def test_rewards_rejects_invalid_nested_records(invalid_record: dict[str, object]) -> None:
    """Reject malformed selected reward and invitation/bonus records."""
    rewards = {**_REWARDS["userRewardsData"], "acceptedRewards": [invalid_record]}
    response = {"data": {"me": _REWARDS["me"], "userRewardsData": rewards}}
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, return_value=response),
        pytest.raises(RequestException),
    ):
        await client.user_rewards_data()


@pytest.mark.asyncio
async def test_rewards_rejects_invalid_user_settings() -> None:
    """Require selected fields from a populated UserSettings record."""
    response = {
        "data": {
            "me": {"id": "synthetic-account", "UserSettings": {}},
            "userRewardsData": _REWARDS["userRewardsData"],
        }
    }
    client = FrankEnergie(auth_token="synthetic-access-token")
    with (
        patch.object(client, "_query", new_callable=AsyncMock, return_value=response),
        pytest.raises(RequestException),
    ):
        await client.user_rewards_data()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    (
        [1],
        "invalid-envelope",
        {"data": {"appVersion": _APP_VERSION}, "errors": "invalid"},
        {"data": {"appVersion": _APP_VERSION}, "errors": None},
        {"data": {"appVersion": _APP_VERSION}, "errors": {"message": "invalid"}},
    ),
)
async def test_app_version_rejects_malformed_http_envelope(aresponses, payload: object) -> None:
    """Reject malformed HTTP GraphQL envelopes before shared error processing."""
    aresponses.add(
        "frank-graphql-prod.graphcdn.app",
        "/",
        "POST",
        aresponses.Response(text=json.dumps(payload), status=200, headers={"Content-Type": "application/json"}),
    )
    async with aiohttp.ClientSession() as session:
        client = FrankEnergie(session, auth_token="synthetic-access-token")
        with pytest.raises(RequestException):
            await client.app_version()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_message",
    ("Graphql validation error", "synthetic unknown provider error with hidden-marker"),
)
async def test_rewards_http_error_redacts_sensitive_payload(
    aresponses, caplog: pytest.LogCaptureFixture, error_message: str
) -> None:
    """Keep partial reward responses and nested upstream errors out of logs."""
    sensitive_payload = {
        "data": {
            "me": {"id": "synthetic-private-account-id"},
            "userRewardsData": {"acceptedRewards": [{"InviteLink": {"fromName": "synthetic-private-referrer"}}]},
        },
        "errors": [
            {
                "message": error_message,
                "extensions": {"account": "synthetic-private-extension"},
                "path": ["synthetic-private-path"],
            }
        ],
    }
    aresponses.add(
        "frank-graphql-prod.graphcdn.app",
        "/",
        "POST",
        aresponses.Response(
            text=json.dumps(sensitive_payload), status=200, headers={"Content-Type": "application/json"}
        ),
    )
    async with aiohttp.ClientSession() as session:
        client = FrankEnergie(session, auth_token="synthetic-access-token")
        with (
            caplog.at_level(logging.DEBUG),
            pytest.raises((FrankEnergieException, RequestException)),
        ):
            await client.user_rewards_data()
    for private_value in (
        "synthetic-private-account-id",
        "synthetic-private-referrer",
        "synthetic-private-extension",
        "synthetic-private-path",
        "hidden-marker",
    ):
        assert private_value not in caplog.text


@pytest.mark.asyncio
async def test_extra_http_rate_limit_preserves_retry_after(aresponses) -> None:
    """Keep provider retry timing and exception classification intact."""
    aresponses.add(
        "frank-graphql-prod.graphcdn.app",
        "/",
        "POST",
        aresponses.Response(
            text=json.dumps({"errors": [{"message": "Too Many Requests"}]}),
            status=200,
            headers={"Content-Type": "application/json", "Retry-After": "27"},
        ),
    )
    async with aiohttp.ClientSession() as session:
        client = FrankEnergie(session, auth_token="synthetic-access-token")
        with pytest.raises(RateLimitException) as raised:
            await client.app_version()
    assert raised.value.retry_after == 27
