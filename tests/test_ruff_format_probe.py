"""Temporary CI probe for formatter discrepancies; delete after collecting the diff."""

import subprocess

import pytest


def test_report_ruff_format_diff() -> None:
    """Print Ruff formatting changes during CI, to resolve existing and new defects."""
    completed = subprocess.run(
        [
            "ruff",
            "format",
            "--diff",
            "python_frank_energie/frank_energie.py",
            "tests/test_smart_batteries.py",
            "scripts/diagnose_frank_battery_status.py",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    pytest.fail("TEMPORARY RUFF FORMAT REPORT:\n" + completed.stdout + completed.stderr, pytrace=False)
