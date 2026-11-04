"""Temporary diagnostic for Ruff formatting differences in PR #215."""

import subprocess


def test_report_ruff_format_diff() -> None:
    """Surface Ruff's exact proposed changes in the pytest CI output."""
    result = subprocess.run(
        ["ruff", "format", "--diff", "python_frank_energie/frank_energie.py", "tests/test_frank_energie.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert not result.stdout and not result.stderr, result.stdout + result.stderr
