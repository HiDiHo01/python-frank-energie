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
    FR = "FR"


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
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
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
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
        _LOGGER.warning("Unknown SmartPvSteeringStatus encountered: %s", value)
        return cls.UNKNOWN


class SmartPvOnboardingStatus(StrEnum):
    """Onboarding status of a Smart PV system."""

    COMPLETED = "COMPLETED"
    COMPLETE_FINAL = "COMPLETE_FINAL"
    ACTIVE = "ACTIVE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "SmartPvOnboardingStatus":
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
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
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
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
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
        _LOGGER.warning("Unknown SmartBatteryMode encountered: %s", value)
        return cls.UNKNOWN


class SmartBatteryImbalanceStrategy(StrEnum):
    """Smart Battery imbalance trading strategy."""

    BALANCED = "balanced"
    CONSERVATIVE = "conservative"
    IMBALANCE_ONLY = "imbalance_only"
    AGGRESSIVE = "aggressive"
    STANDARD = "standard"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "SmartBatteryImbalanceStrategy":
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
        _LOGGER.warning("Unknown SmartBatteryImbalanceStrategy encountered: %s", value)
        return cls.UNKNOWN


class SmartBatteryStatus(StrEnum):
    """Smart Battery operational status."""

    STATUS_CHARGING = "status_charging"
    STATUS_DISCHARGING = "status_discharging"
    STATUS_IDLE = "status_idle"
    STATUS_UNRELIABLE_DATA = "status_unreliable_data"
    STATUS_OFFLINE = "status_offline"
    STATUS_STANDBY = "status_standby"
    SEPARATE_IMBALANCES = "separate_imbalances"
    IDLE_FULL = "idle_full"
    IDLE_PRICE = "idle_price"
    DISCHARGE_SELF_CONSUMPTION = "discharge_self_consumption"
    DISCHARGE_IMBALANCE = "discharge_imbalance"
    CHARGE_IMBALANCE = "charge_imbalance"
    DISCHARGE_INTRADAY = "discharge_intraday"
    CHARGE_INTRADAY = "charge_intraday"
    IDLE_INTRADAY = "idle_intraday"
    CHARGE_EPEX = "charge_epex"
    DISCHARGE_EPEX = "discharge_epex"
    IDLE_EPEX = "idle_epex"
    DISCHARGE_CONGESTION = "discharge_congestion"
    CHARGE_CONGESTION = "charge_congestion"
    DISCHARGE_SELF_CONSUMPTION_MIXED = "discharge_self_consumption_mixed"
    IDLE_CONGESTION = "idle_congestion"
    IDLE_EMPTY = "idle_empty"
    IDLE_FIFTEEN_PERCENT = "idle_fifteen_percent"
    IDLE_FIFTEEN_PERCENTAGE = "idle_fifteen_percentage"
    CHARGE_SELF_CONSUMPTION = "charge_self_consumption"
    CHARGE_SELF_CONSUMPTION_MIXED = "charge_self_consumption_mixed"
    STATUS_MAINTENANCE = "status_maintenance"
    STATUS_ERROR = "status_error"
    DISCHARGE_SMART_HOME = "discharge_smart_home"
    CHARGE_SMART_HOME = "charge_smart_home"
    IDLE_SMART_HOME = "idle_smart_home"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "SmartBatteryStatus":
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
        _LOGGER.warning("Unknown SmartBatteryStatus encountered: %s", value)
        return cls.UNKNOWN


class SessionStatus(StrEnum):
    """Session status for trading/battery sessions."""

    COMPLETED = "COMPLETED"
    COMPLETE_FINAL = "COMPLETE_FINAL"
    COMPLETE_PRELIMINARY = "COMPLETE_PRELIMINARY"
    ACTIVE = "ACTIVE"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value: object) -> "SessionStatus":
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
        _LOGGER.warning("Unknown SessionStatus encountered: %s", value)
        return cls.UNKNOWN


class ServiceStatus(StrEnum):
    """Generic service status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    DELIVERY_ENDED = "delivery_ended"
    IN_DELIVERY = "in_delivery"
    READY = "ready"
    SWITCHED = "switched"
    LOSS = "loss"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value: object) -> "ServiceStatus":
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
        _LOGGER.warning("Unknown ServiceStatus encountered: %s", value)
        return cls.UNKNOWN
