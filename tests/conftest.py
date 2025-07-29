import json
import pytest
from pathlib import Path


@pytest.fixture
def smart_battery_sessions():
    """Load smartBatterySessions.json as dict."""
    fixture_path = Path(__file__).parent / "fixtures" / "smartBatterySessions.json"

    if not fixture_path.exists():
        raise FileNotFoundError("Missing test fixture: smartBatterySessions.json")

    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)
