"""Domain-specific enumerations for the Frank Energie integration."""

# domain.py
# version 2026.05.31
import logging
from enum import StrEnum

_LOGGER = logging.getLogger(__name__)


class EnergyType(StrEnum):
    """Supported energy types."""

    ELECTRICITY = "electricity"
    GAS = "gas"


class CountryCode(StrEnum):
    """Supported country codes."""

    NL = "NL"
    BE = "BE"


class Resolution(StrEnum):
    """Supported price resolutions."""

    PT15M = "PT15M"
    PT60M = "PT60M"


class SmartPvOperationalStatus(StrEnum):
    """Operational status of a Smart PV system."""

    ON = "ON"
    OFF = "OFF"
    OPERATIONAL = "OPERATIONAL"
    NO_CONNECTION = "NO_CONNECTION"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "SmartPvOperationalStatus":
        _LOGGER.warning("Unknown SmartPvOperationalStatus encountered: %s", value)
        return cls.UNKNOWN


class SmartPvSteeringStatus(StrEnum):
    """Steering status of a Smart PV system."""

    ACTIVE = "ACTIVE"
    STEERING = "STEERING"
    NO_STEERING = "NO_STEERING"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "SmartPvSteeringStatus":
        _LOGGER.warning("Unknown SmartPvSteeringStatus encountered: %s", value)
        return cls.UNKNOWN


class SmartPvOnboardingStatus(StrEnum):
    """Onboarding status of a Smart PV system."""

    COMPLETED = "COMPLETED"
    ACTIVE = "ACTIVE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "SmartPvOnboardingStatus":
        _LOGGER.warning("Unknown SmartPvOnboardingStatus encountered: %s", value)
        return cls.UNKNOWN


class PowerDeliveryState(StrEnum):
    """Power delivery state for EV chargers."""

    UNPLUGGED = "UNPLUGGED"
    PLUGGED_IN_CHARGING = "PLUGGED_IN:CHARGING"
    PLUGGED_IN_NOT_CHARGING = "PLUGGED_IN:NOT_CHARGING"
    PLUGGED_IN_FINISHED = "PLUGGED_IN:FINISHED"
    PLUGGED_IN_NO_POWER = "PLUGGED_IN:NO_POWER"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "PowerDeliveryState":
        _LOGGER.warning("Unknown PowerDeliveryState encountered: %s", value)
        return cls.UNKNOWN


class SmartBatteryMode(StrEnum):
    """Smart Battery mode."""

    IMBALANCE_TRADING = "imbalance_trading"
    SELF_CONSUMPTION = "self_consumption"
    SELF_CONSUMPTION_MIX = "self_consumption_mix"
    TRADING = "trading"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "SmartBatteryMode":
        _LOGGER.warning("Unknown SmartBatteryMode encountered: %s", value)
        return cls.UNKNOWN


class SmartBatteryImbalanceStrategy(StrEnum):
    """Smart Battery imbalance trading strategy."""

    BALANCED = "balanced"
    CONSERVATIVE = "conservative"
    IMBALANCE_ONLY = "imbalance_only"
    AGGRESSIVE = "aggressive"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "SmartBatteryImbalanceStrategy":
        _LOGGER.warning("Unknown SmartBatteryImbalanceStrategy encountered: %s", value)
        return cls.UNKNOWN


class SessionStatus(StrEnum):
    """Session status for trading/battery sessions."""

    COMPLETED = "COMPLETED"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "SessionStatus":
        _LOGGER.warning("Unknown SessionStatus encountered: %s", value)
        return cls.UNKNOWN


class ServiceStatus(StrEnum):
    """Generic service status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DELIVERY_ENDED = "delivery_ended"
    IN_DELIVERY = "in_delivery"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "ServiceStatus":
        _LOGGER.warning("Unknown ServiceStatus encountered: %s", value)
        return cls.UNKNOWN
