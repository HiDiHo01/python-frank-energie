import pytest

from python_frank_energie.domain import (
    PowerDeliveryState,
    ServiceStatus,
    SessionStatus,
    SmartBatteryImbalanceStrategy,
    SmartBatteryMode,
    SmartBatteryStatus,
    SmartPvOnboardingStatus,
    SmartPvOperationalStatus,
    SmartPvSteeringStatus,
)


@pytest.mark.parametrize(
    ("enum_cls", "valid_member_name", "valid_value"),
    [
        (ServiceStatus, "ACTIVE", "ACTIVE"),
        (PowerDeliveryState, "UNPLUGGED", "UNPLUGGED"),
        (PowerDeliveryState, "PLUGGED_IN_STOPPED", "PLUGGED_IN:STOPPED"),
        (PowerDeliveryState, "PLUGGED_IN_INITIALIZING", "PLUGGED_IN:INITIALIZING"),
        (PowerDeliveryState, "PLUGGED_IN_COMPLETE", "PLUGGED_IN:COMPLETE"),
        (SessionStatus, "PENDING", "PENDING"),
        (SmartBatteryMode, "IMBALANCE_TRADING", "imbalance_trading"),
        (SmartBatteryImbalanceStrategy, "BALANCED", "balanced"),
        (SmartBatteryImbalanceStrategy, "STANDARD", "standard"),
        (SmartBatteryStatus, "STATUS_IDLE", "status_idle"),
        (SmartPvOperationalStatus, "ON", "ON"),
        (SmartPvSteeringStatus, "ACTIVE", "ACTIVE"),
        (SmartPvOnboardingStatus, "COMPLETED", "COMPLETED"),
    ],
)
def test_enum_case_insensitive_parsing(enum_cls, valid_member_name: str, valid_value: str) -> None:
    """Test that lower/upper-cased inputs resolve to the correct enum member."""
    member = enum_cls[valid_member_name]
    assert enum_cls(valid_value.lower()) is member
    assert enum_cls(valid_value.upper()) is member
    assert enum_cls(valid_value.capitalize()) is member


@pytest.mark.parametrize(
    "enum_cls",
    [
        ServiceStatus,
        PowerDeliveryState,
        SessionStatus,
        SmartBatteryMode,
        SmartBatteryImbalanceStrategy,
        SmartBatteryStatus,
        SmartPvOperationalStatus,
        SmartPvSteeringStatus,
        SmartPvOnboardingStatus,
    ],
)
def test_enum_unknown_and_none_fall_back_to_unknown(enum_cls) -> None:
    """Test that unknown or None values consistently fall back to UNKNOWN."""
    assert enum_cls("GARBAGE_VALUE") is enum_cls.UNKNOWN
    assert enum_cls("") is enum_cls.UNKNOWN
    assert enum_cls(None) is enum_cls.UNKNOWN
    # An unhashable value must still fall back rather than raise while the
    # warning is de-duplicated.
    assert enum_cls(["unexpected", "list"]) is enum_cls.UNKNOWN


def test_unknown_enum_value_is_warned_once(caplog) -> None:
    """A given unrecognised value is logged once, not on every lookup.

    ``_missing_`` runs on every API poll, so without de-duplication a status
    added server-side floods the log until it ships as an enum member.
    """
    import logging

    from python_frank_energie import domain

    domain._warned_unknown_enum_values.discard(("SmartPvSteeringStatus", repr("FLOOD")))

    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            assert SmartPvSteeringStatus("FLOOD") is SmartPvSteeringStatus.UNKNOWN

    warnings = [
        record for record in caplog.records if record.getMessage() == "Unknown SmartPvSteeringStatus encountered: FLOOD"
    ]
    assert len(warnings) == 1
