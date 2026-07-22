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
