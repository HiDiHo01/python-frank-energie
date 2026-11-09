"""Regression tests for the cross-repository dependency release synchronizer."""

import json
import tomllib
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
    poetry = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["tool"]["poetry"]
    assert poetry["version"] == "2026.9.20"
    assert poetry["dependencies"]["python-frank-energie"] == "==2026.11.9"


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


def test_updates_an_existing_exact_poetry_constraint(tmp_path: Path) -> None:
    """A later release can replace an exact pin from an earlier automated PR."""
    _, pyproject_path = _make_checkout(tmp_path, "2026.11.9")
    source = pyproject_path.read_text(encoding="utf-8")
    pyproject_path.write_text(source.replace("^2026.11.9", "==2026.11.9"), encoding="utf-8")

    assert update_dependency(tmp_path, "2026.11.10") is True
    assert pyproject_path.read_text(encoding="utf-8") == source.replace("^2026.11.9", "==2026.11.10")


def test_exact_constraint_is_idempotent(tmp_path: Path) -> None:
    """A repeated release event must not modify an already-pinned dependency."""
    manifest_path, pyproject_path = _make_checkout(tmp_path, "2026.11.9")
    source = pyproject_path.read_text(encoding="utf-8")
    pyproject_path.write_text(source.replace("^2026.11.9", "==2026.11.9"), encoding="utf-8")
    before = manifest_path.read_bytes(), pyproject_path.read_bytes()

    assert update_dependency(tmp_path, "2026.11.9") is False
    assert (manifest_path.read_bytes(), pyproject_path.read_bytes()) == before


def test_mismatched_version_contract_does_not_modify_files(tmp_path: Path) -> None:
    """Reject drift between the manifest pin and the Poetry constraint."""
    manifest_path, pyproject_path = _make_checkout(tmp_path)
    text = pyproject_path.read_text(encoding="utf-8").replace("^2026.9.20", "^2026.9.21")
    pyproject_path.write_text(text, encoding="utf-8")
    previous_manifest = manifest_path.read_bytes()
    with pytest.raises(ValueError, match="must match"):
        update_dependency(tmp_path, "2026.11.9")
    assert manifest_path.read_bytes() == previous_manifest
    assert pyproject_path.read_text(encoding="utf-8") == text


@pytest.mark.parametrize(
    "duplicate",
    ["python-frank-energie==2026.9.20", "python-frank-energie[extra]", "Python_Frank_Energie>=2026.9.20"],
)
def test_duplicate_package_requirement_is_rejected(tmp_path: Path, duplicate: str) -> None:
    """Do not silently update ambiguous or duplicate dependency entries."""
    manifest_path, _ = _make_checkout(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["requirements"].append(duplicate)
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


def test_similarly_prefixed_packages_do_not_block_the_library_pin(tmp_path: Path) -> None:
    """Ignore unrelated distributions whose names share the library prefix."""
    manifest_path, _ = _make_checkout(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["requirements"].append("python-frank-energie-extras==1.0")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    assert update_dependency(tmp_path, "2026.11.9") is True
    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert updated["requirements"] == ["python-frank-energie==2026.11.9", "python-frank-energie-extras==1.0"]


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_preserves_alternative_toml_whitespace_and_inline_comments(tmp_path: Path, newline: str) -> None:
    """Update a parsed dependency while keeping its existing TOML layout."""
    _, pyproject_path = _make_checkout(tmp_path)
    original = pyproject_path.read_text(encoding="utf-8")
    spaced = original.replace(
        'python-frank-energie = "^2026.9.20"',
        "'python-frank-energie'  =  '^2026.9.20' # preserve this comment",
    ).replace("\n", newline)
    pyproject_path.write_bytes(spaced.encode("utf-8"))

    assert update_dependency(tmp_path, "2026.11.9") is True
    assert pyproject_path.read_bytes().decode("utf-8") == spaced.replace("^2026.9.20", "==2026.11.9")


@pytest.mark.parametrize("failed_file", ["pyproject.toml", "manifest.json"])
def test_failed_replacement_leaves_both_declarations_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_file: str,
) -> None:
    """Keep both original files if either staged file cannot replace its destination."""
    manifest_path, pyproject_path = _make_checkout(tmp_path)
    previous_manifest = manifest_path.read_bytes()
    previous_poetry = pyproject_path.read_bytes()
    original_replace = Path.replace

    def replace_or_fail(source: Path, destination: Path) -> Path:
        """Fail the selected staged replacement and allow any rollback."""
        if source.name == failed_file:
            raise OSError("Synthetic replacement failure")
        return original_replace(source, destination)

    monkeypatch.setattr(Path, "replace", replace_or_fail)
    with pytest.raises(OSError, match="Synthetic replacement failure"):
        update_dependency(tmp_path, "2026.11.9")

    assert manifest_path.read_bytes() == previous_manifest
    assert pyproject_path.read_bytes() == previous_poetry


@pytest.mark.parametrize(
    ("current", "locked", "needs_update"),
    [("2026.11.9", "2026.9.20", True), ("2026.11.9", "2026.11.9", False), ("2026.12.1", "2026.9.20", False)],
)
def test_prepare_lock_checks_the_current_main_version(
    tmp_path: Path, current: str, locked: str, needs_update: bool
) -> None:
    """Repair the current release's stale lock without proposing an older release."""
    manifest_path, pyproject_path = _make_checkout(tmp_path, current)
    (tmp_path / "poetry.lock").write_text(
        f'[[package]]\nname = "python-frank-energie"\nversion = "{locked}"\n', encoding="utf-8"
    )
    previous_manifest = manifest_path.read_bytes()
    previous_pyproject = pyproject_path.read_text(encoding="utf-8")

    assert update_dependency(tmp_path, "2026.11.9", prepare_lock=True) is needs_update
    assert manifest_path.read_bytes() == previous_manifest
    expected_pyproject = previous_pyproject.replace("^2026.11.9", "==2026.11.9") if needs_update else previous_pyproject
    assert pyproject_path.read_text(encoding="utf-8") == expected_pyproject


def test_rejects_noncanonical_target_version(tmp_path: Path) -> None:
    """Require a normalized release version in the synchronization script."""
    _make_checkout(tmp_path)
    with pytest.raises(ValueError, match="Non-canonical"):
        update_dependency(tmp_path, "2026.09.09")


def test_cli_handles_validation_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Return a clear CLI error without writing malformed release data."""
    from scripts.sync_home_assistant_dependency import main

    _make_checkout(tmp_path)
    with pytest.raises(SystemExit, match="2"):
        main(["--root", str(tmp_path), "--version", "invalid-version"])
    error = capsys.readouterr().err.splitlines()[-1].partition(": error: ")[2]
    assert error.startswith("Cannot safely synchronize")
