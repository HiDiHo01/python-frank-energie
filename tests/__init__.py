"""Tests for python-frank-energie."""

import os
from typing import Final


def load_fixtures(filename: str) -> str:
    """Load a fixture from the fixtures directory.

    Args:
        filename: The name of the fixture file.

    Returns:
        The contents of the fixture file as a string.

    Raises:
        FileNotFoundError: If the fixture file does not exist.
    """
    fixtures_dir: Final[str] = os.path.join(os.path.dirname(__file__), "fixtures")
    fixture_path: Final[str] = os.path.join(fixtures_dir, filename)

    if not os.path.exists(fixture_path):
        raise FileNotFoundError(f"Fixture file not found: %s" % fixture_path)

    with open(fixture_path, encoding="utf-8") as file:
        return file.read()
