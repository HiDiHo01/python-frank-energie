import pytest

from custom_components.frank_energie.enode.battery import parse_sessions


def test_parse_smart_battery_sessions(smart_battery_sessions):
    """Test parsing of smart battery sessions fixture."""
    sessions: list[BatterySession] = parse_sessions(smart_battery_sessions)

    assert isinstance(sessions, list)
    assert len(sessions) > 0

    first = sessions[0]
    assert hasattr(first, "start")
    assert hasattr(first, "end")
    assert first.energy_kwh > 0
