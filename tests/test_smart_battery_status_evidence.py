"""Regression tests for observed Smart Battery status combinations."""

from python_frank_energie.domain import (
    SmartBatteryActivityStatus,
    SmartBatteryConnectionStatus,
    SmartBatteryGridCongestionStatus,
)
from python_frank_energie.models import SmartBatteryStatus, SmartBatterySummary


def test_sessy_summary_preserves_independent_status_fields() -> None:
    """Keep the observed Sessy activity, connection and congestion states independent of steering."""
    summary = SmartBatterySummary.from_dict(
        {
            "lastKnownStateOfCharge": 50,
            "lastKnownStatus": None,
            "lastUpdate": "2026-11-24T11:56:53.892Z",
            "totalResult": 1.5,
            "activityStatus": "CHARGING",
            "status": "CONNECTED",
            "gridCongestionStatus": "ENROLLED",
        }
    )

    assert summary.activity_status is SmartBatteryActivityStatus.CHARGING
    assert summary.connection_status is SmartBatteryConnectionStatus.CONNECTED
    assert summary.grid_congestion_status is SmartBatteryGridCongestionStatus.ENROLLED
    assert summary.last_known_status is SmartBatteryStatus.UNKNOWN


def test_enrolled_grid_congestion_status_is_a_supported_observed_value() -> None:
    """Parse the provider-observed ENROLLED value without using inferred ACTIVE."""
    assert SmartBatteryGridCongestionStatus("ENROLLED") is SmartBatteryGridCongestionStatus.ENROLLED
