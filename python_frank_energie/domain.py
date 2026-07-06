"""Domain-specific enumerations for the Frank Energie integration."""

# domain.py
# version 2026.05.31
from enum import StrEnum
import logging

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
