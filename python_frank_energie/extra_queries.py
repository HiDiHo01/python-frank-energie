"""Read-only GraphQL selections and conservative response validation.

These five selections originated from historical comments in frank_energie.py.
They have not been verified against a current provider schema. Keep returned
values unchanged and distinguish explicit nulls from malformed responses.
"""

from __future__ import annotations

from .exceptions import RequestException

USER_SMART_CHARGING_QUERY = """
    query UserSmartCharging {
        userSmartCharging {
            isActivated
            provider
            userCreatedAt
            userId
            isAvailableInCountry
            needsSubscription
            subscription {
                startDate
                endDate
                id
                proposition {
                    product
                    countryCode
                }
            }
        }
    }
"""

APP_VERSION_QUERY = """
    query AppVersion {
        appVersion {
            ios {
                version
            }
            android {
                version
            }
        }
    }
"""

USER_REWARDS_DATA_QUERY = """
    query UserRewardsData {
        me {
            id
            UserSettings {
                id
                rewardPayoutPreference
            }
        }
        userRewardsData {
            activeConnectionsCount
            activeFriendsCount
            acceptedRewards {
                ...UserRewardV2Fields
            }
            upcomingRewards {
                ...UserRewardV2Fields
            }
        }
    }

    fragment UserRewardV2Fields on UserRewardV2 {
        id
        awardedDiscount
        awardedTreesAmount
        availableForAcceptanceOn
        treesAmountPerConnection
        discountPerConnection
        acceptedOn
        isRewardForOwnSignup
        hasPossibleSmartChargingBonus
        coolingDownPeriod
        InviteLink {
            id
            type
            fromName
            templateType
            awardRewardType
            treesAmountPerConnection
            discountPerConnection
        }
        AdditionalBonuses {
            discountAmountPerConnection
            treesAmountPerConnection
            type
        }
    }
"""

TREE_CERTIFICATES_QUERY = """
    query TreeCertificates {
        treeCertificates {
            id
            imageUrl
            imagePath
            createdAt
            treesAmount
        }
    }
"""

APP_NOTICE_QUERY = """
    query AppNotice {
        appNotice {
            active
            message
            title
        }
    }
"""


def _graphql_root(response: object, field_name: str) -> object:
    """Return an explicitly present root field from a successful GraphQL response."""
    if not isinstance(response, dict):
        raise RequestException(f"Invalid {field_name} response: expected a GraphQL object")
    if "errors" in response:
        errors = response["errors"]
        if not isinstance(errors, list) or errors:
            raise RequestException(f"Invalid {field_name} response: GraphQL errors are present")
    data = response.get("data")
    if not isinstance(data, dict) or field_name not in data:
        raise RequestException(f"Invalid {field_name} response: missing root field")
    return data[field_name]


def _validate_record(value: object, field_name: str, required_fields: frozenset[str]) -> dict[str, object]:
    """Validate the selected keys without coercing provider-supplied values."""
    if not isinstance(value, dict) or not required_fields.issubset(value):
        raise RequestException(f"Invalid {field_name} response: expected an object with selected fields")
    return value


def optional_record(response: object, field_name: str, required_fields: frozenset[str]) -> dict[str, object] | None:
    """Preserve an explicit null, otherwise require a complete selected record."""
    value = _graphql_root(response, field_name)
    if value is None:
        return None
    return _validate_record(value, field_name, required_fields)


def optional_records(
    response: object, field_name: str, required_fields: frozenset[str]
) -> list[dict[str, object]] | None:
    """Return a verified list; never confuse malformed or null data with an empty list."""
    value = _graphql_root(response, field_name)
    if value is None:
        return None
    if not isinstance(value, list):
        raise RequestException(f"Invalid {field_name} response: expected a list or null")
    return [_validate_record(item, field_name, required_fields) for item in value]


def app_version_response(response: object) -> dict[str, object] | None:
    """Validate nested platform records while preserving null values and versions."""
    app_version = optional_record(response, "appVersion", frozenset({"ios", "android"}))
    if app_version is None:
        return None
    for platform in ("ios", "android"):
        platform_record = app_version[platform]
        if platform_record is None:
            continue
        details = _validate_record(platform_record, f"appVersion.{platform}", frozenset({"version"}))
        version = details["version"]
        if version is not None and not isinstance(version, str):
            raise RequestException(f"Invalid appVersion.{platform} response: version must be a string or null")
    return app_version


_REWARD_FIELDS = frozenset(
    {
        "id",
        "awardedDiscount",
        "awardedTreesAmount",
        "availableForAcceptanceOn",
        "treesAmountPerConnection",
        "discountPerConnection",
        "acceptedOn",
        "isRewardForOwnSignup",
        "hasPossibleSmartChargingBonus",
        "coolingDownPeriod",
        "InviteLink",
        "AdditionalBonuses",
    }
)
_INVITE_LINK_FIELDS = frozenset(
    {
        "id",
        "type",
        "fromName",
        "templateType",
        "awardRewardType",
        "treesAmountPerConnection",
        "discountPerConnection",
    }
)
_BONUS_FIELDS = frozenset({"discountAmountPerConnection", "treesAmountPerConnection", "type"})


def _validate_reward(record: object, field_name: str) -> None:
    """Check selected reward fields and nested records without changing their values."""
    reward = _validate_record(record, field_name, _REWARD_FIELDS)
    invite_link = reward["InviteLink"]
    if invite_link is not None:
        _validate_record(invite_link, f"{field_name}.InviteLink", _INVITE_LINK_FIELDS)
    bonuses = reward["AdditionalBonuses"]
    if bonuses is None:
        return
    if not isinstance(bonuses, list):
        raise RequestException(f"Invalid {field_name}.AdditionalBonuses response: expected a list or null")
    for bonus in bonuses:
        _validate_record(bonus, f"{field_name}.AdditionalBonuses", _BONUS_FIELDS)


def _validate_reward_list(rewards: dict[str, object], field_name: str) -> None:
    """Require reward collections to be lists or explicit nulls."""
    entries = rewards[field_name]
    if entries is None:
        return
    if not isinstance(entries, list):
        raise RequestException(f"Invalid userRewardsData response: {field_name} must be a list or null")
    for entry in entries:
        _validate_reward(entry, f"userRewardsData.{field_name}")


def rewards_response(response: object) -> dict[str, dict[str, object] | None]:
    """Retain both selected roots, including independently nullable results."""
    me = optional_record(response, "me", frozenset({"id", "UserSettings"}))
    if me is not None and me["UserSettings"] is not None:
        _validate_record(me["UserSettings"], "me.UserSettings", frozenset({"id", "rewardPayoutPreference"}))
    rewards = optional_record(
        response,
        "userRewardsData",
        frozenset({"activeConnectionsCount", "activeFriendsCount", "acceptedRewards", "upcomingRewards"}),
    )
    if rewards is not None:
        for field_name in ("acceptedRewards", "upcomingRewards"):
            _validate_reward_list(rewards, field_name)
    return {"me": me, "userRewardsData": rewards}
