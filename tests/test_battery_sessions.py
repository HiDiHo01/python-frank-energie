import pytest
from datetime import datetime, timezone, date

# Import the function or class you are testing
from python_frank_energie.models import BatterySession, parse_sessions

def test_parse_smart_battery_sessions(smart_battery_sessions: dict):
    """Validate parsing of smartBatterySessions.json fixture into BatterySession objects."""
    assert "data" in smart_battery_sessions, "Missing 'data' root key in fixture."
    assert (
        "smartBatterySessions" in smart_battery_sessions["data"]
    ), "Missing 'smartBatterySessions' key inside 'data'."
    # Extract sessions from data
    data = smart_battery_sessions["data"]["smartBatterySessions"]

    sessions: list[BatterySession] = parse_sessions(data)

    # Validate list integrity
    assert isinstance(sessions, list)
    assert len(sessions) == len(data["sessions"])
    assert len(sessions) > 0
    assert sessions, "Expected at least one session in the fixture"

    # Validate first session fields
    first = sessions[0]
    assert isinstance(first, BatterySession)
    assert isinstance(first.date, date)
    assert first.status in ("COMPLETE_FINAL", "COMPLETE_PRELIMINARY", "ACTIVE")

    # Check attributes match expected model
    assert hasattr(first, "start")
    assert hasattr(first, "end")
    assert hasattr(first, "cumulative_result")
    assert hasattr(first, "result")
    
    assert first.cumulative_result >= first.result
