"""Exercise the published documentation retry policy without network access."""

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/docs.yml"
_SITE_URL = "https://hidiho01.github.io/python-frank-energie/"
_MOCK_COMMANDS = r"""
SITE_URL=$1
scenario=$2
SECONDS=0
sleep() { SECONDS=$((SECONDS + $1)); }
curl() {
  local url=${@: -1}
  printf 'request %s\n' "$url" >&2
  if [[ "$url" == "${SITE_URL}getting-started/" ]]; then
    case "$scenario" in
      delayed) if (( SECONDS < 120 )); then printf 404; return; fi ;;
      missing) printf 404; return ;;
      redirect) printf 302; return ;;
      network) printf 000; return 7 ;;
    esac
  fi
  printf 200
}
"""


@pytest.mark.parametrize(
    ("scenario", "expected_exit"),
    [("ready", 0), ("delayed", 0), ("missing", 1), ("redirect", 1), ("network", 1)],
)
def test_public_pages_retry_window(scenario: str, expected_exit: int) -> None:
    """Retry only failed routes, allow propagation, and reject persistent errors."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("The GitHub Pages verification step requires Bash")
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    _, marker, step = workflow.partition("      - name: Check public documentation URLs\n")
    assert marker
    _, marker, script = step.partition("        run: |\n")
    assert marker
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-c", _MOCK_COMMANDS + textwrap.dedent(script), "verify", _SITE_URL, scenario],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == expected_exit, result.stdout + result.stderr
    requests = result.stderr.splitlines()
    assert len(set(requests)) == 12
    failed_url = f"{_SITE_URL}getting-started/"
    retries = requests.count(f"request {failed_url}")
    assert len(requests) == 11 + retries
    if scenario == "ready":
        assert retries == 1
    else:
        assert 6 <= retries <= 17
    if expected_exit:
        assert f"::error::Published page is not reachable: {failed_url}" in result.stdout
    else:
        assert "::error::" not in result.stdout
        assert f"HTTP 200: {failed_url}" in result.stdout
