"""Domain-specific enumerations for the Frank Energie integration."""

from enum import StrEnum


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