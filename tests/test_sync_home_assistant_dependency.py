"""Regression tests for the cross-repository dependency release synchronizer."""

import json
from pathlib import Path

import pytest

from scripts.sync_home_assistant_dependency import update_dependency


def _make_checkout(tmp_path: Path, version: str = "2026.9.20") -> tuple[Path, Path]:
    """Create an isolated Home Assistant integration with matching dependencies."""
    manifest_path = tmp_path / "custom_components" / "frank_energie" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "domain": "frank_energie",
                "requirements": [f"python-frank-energie=={version}"],
                "version": "2026.9.20",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    pyproject_path = tmp_path / "pyproject.toml"
    pyproject_path.write_text(
        f'[tool.poetry]\nname = "home-assistant-frank_energie"\nversion = "2026.9.20"\n'
        f'[tool.poetry.dependencies]\npython = ">=3.14.2,<4"\npython-frank-energie = "^{version}"\n',
        encoding="utf-8",
    )
    return manifest_path, pyproject_path


def test_updates_only_library_dependency_and_keeps_integration_version(tmp_path: Path) -> None:
    """Keep the HA integration's independent release version unchanged."""
    manifest_path, pyproject_path = _make_checkout(tmp_path)
    assert update_dependency(tmp_path, "2026.11.9") is True
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["requirements"] == ["python-frank-energie==2026.11.9"]
    assert manifest["version"] == "2026.9.20"
    assert 'version = "2026.9.20"' in pyproject_path.read_text(encoding="utf-8")
    assert 'python-frank-energie = "^2026.11.9"' in pyproject_path.read_text(encoding="utf-8")


@pytest.mark.parametrize(("current", "target"), [("2026.11.9", "2026.11.9"), ("2026.12.1", "2026.11.9")])
def test_noop_for_equal_or_older_release(tmp_path: Path, current: str, target: str) -> None:
    """Ignore repeated releases and out-of-order older release publications."""
    manifest_path, pyproject_path = _make_checkout(tmp_path, current)
    before = (manifest_path.read_bytes(), pyproject_path.read_bytes())
    assert update_dependency(tmp_path, target) is False
    assert (manifest_path.read_bytes(), pyproject_path.read_bytes()) == before


@pytest.mark.parametrize("version", ["v2026.11.9", "2026.11.9rc1", "2026.2.30", "2026.11.9; bad", "../2026.11.9"])
def test_rejects_invalid_target_versions_without_writing(tmp_path: Path, version: str) -> None:
    """Never interpolate invalid, prerelease, or impossible calendar versions."""
    manifest_path, pyproject_path = _make_checkout(tmp_path)
    before = (manifest_path.read_bytes(), pyproject_path.read_bytes())
    with pytest.raises(ValueError):
        update_dependency(tmp_path, version)
    assert (manifest_path.read_bytes(), pyproject_path.read_bytes()) == before


def test_mismatched_version_contract_does_not_modify_files(tmp_path: Path) -> None:
    """Reject drift between the manifest pin and the Poetry constraint."""
    manifest_path, pyproject_path = _make_checkout(tmp_path)
    text = pyproject_path.read_text(encoding="utf-8").replace("^2026.9.20", "^2026.9.21")
    pyproject_path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="must match"):
        update_dependency(tmp_path, "2026.11.9")
    assert "2026.9.20" in manifest_path.read_text(encoding="utf-8")
    assert "^2026.9.21" in pyproject_path.read_text(encoding="utf-8")


def test_duplicate_package_requirement_is_rejected(tmp_path: Path) -> None:
    """Do not silently update ambiguous or duplicate dependency entries."""
    manifest_path, _ = _make_checkout(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["requirements"].append("python-frank-energie==2026.9.20")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one"):
        update_dependency(tmp_path, "2026.11.9")


def test_ignores_unrelated_manifest_dependencies(tmp_path: Path) -> None:
    """Preserve unrelated manifest requirements and the exact manifest layout."""
    manifest_path, _ = _make_checkout(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["requirements"].append("some-other-package==1.2.3")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    assert update_dependency(tmp_path, "2026.11.9") is True
    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert updated["requirements"] == ["python-frank-energie==2026.11.9", "some-other-package==1.2.3"]


def test_cli_handles_validation_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Return a clear CLI error without writing malformed release data."""
    from scripts.sync_home_assistant_dependency import main

    _make_checkout(tmp_path)
    with pytest.raises(SystemExit, match="2"):
        main(["--root", str(tmp_path), "--version", "invalid-version"])
    assert "Cannot safely synchronize" in capsys.readouterr().err
