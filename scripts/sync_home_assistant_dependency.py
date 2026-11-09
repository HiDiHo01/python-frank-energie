"""Synchronize the Frank Energie library requirement in a Home Assistant checkout."""

import argparse
import json
import re
import shutil
import stat
import tomllib
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory

PACKAGE_NAME = "python-frank-energie"
VERSION = r"\d{4}\.\d{1,2}\.\d{1,2}"
VERSION_PATTERN = re.compile(VERSION, re.ASCII)
MANIFEST_PIN = re.compile(rf"{PACKAGE_NAME}==(?P<version>{VERSION})", re.ASCII)
DISTRIBUTION_NAME = re.compile(r"\s*([a-z0-9][a-z0-9._-]*)", re.IGNORECASE | re.ASCII)
POETRY_PATTERN = re.compile(
    r"""^[ \t]*(?P<key_quote>['"]?)python-frank-energie(?P=key_quote)[ \t]*=[ \t]*(?P<quote>['"])"""
    rf"(?P<constraint>(?:\^|==)(?P<version>{VERSION}))"
    r"(?P=quote)[ \t]*(?:#[^\r\n]*)?\r?$",
    re.ASCII | re.MULTILINE,
)


def _version_parts(version: str) -> tuple[int, int, int]:
    """Validate a stable calendar version before comparing release ordering."""
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(f"Invalid stable python-frank-energie version: {version!r}")
    year, month, day = (int(part) for part in version.split("."))
    date(year, month, day)
    if version != f"{year}.{month}.{day}":
        raise ValueError(f"Non-canonical calendar release version: {version!r}")
    return year, month, day


def _is_library_requirement(requirement: object) -> bool:
    """Match the complete distribution name, including normalized aliases."""
    if not isinstance(requirement, str):
        return False
    name = DISTRIBUTION_NAME.match(requirement)
    return name is not None and re.sub(r"[-_.]+", "-", name[1].lower()) == PACKAGE_NAME


def _current_version(manifest_text: str, pyproject_text: str) -> str:
    """Require exactly one matching manifest pin and Poetry dependency."""
    manifest = json.loads(manifest_text)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("requirements"), list):
        raise ValueError("Expected an integration manifest object with a requirements list")

    matching = [requirement for requirement in manifest["requirements"] if _is_library_requirement(requirement)]
    if len(matching) != 1 or (pin := MANIFEST_PIN.fullmatch(matching[0])) is None:
        raise ValueError("Expected exactly one pinned python-frank-energie manifest requirement")

    version = pin["version"]
    _version_parts(version)
    pyproject = tomllib.loads(pyproject_text)
    declared = pyproject.get("tool", {}).get("poetry", {}).get("dependencies", {}).get(PACKAGE_NAME)
    declarations = list(POETRY_PATTERN.finditer(pyproject_text))
    if (
        declared not in (f"^{version}", f"=={version}")
        or len(declarations) != 1
        or declarations[0].group("version") != version
    ):
        raise ValueError("Poetry's python-frank-energie dependency must match the pinned manifest version")
    return version


def _locked_versions(root: Path) -> list[str]:
    """Read the locked versions of the library, allowing a missing lockfile."""
    try:
        with (root / "poetry.lock").open("rb") as source:
            lock = tomllib.load(source)
    except FileNotFoundError:
        return []
    return [package["version"] for package in lock.get("package", []) if package["name"] == PACKAGE_NAME]


def _replace_declarations(manifest: Path, manifest_text: str, project: Path, project_text: str) -> None:
    """Stage both files before replacing them and roll back a failed second replacement."""
    with TemporaryDirectory(dir=manifest.parent) as manifest_dir, TemporaryDirectory(dir=project.parent) as project_dir:
        staged_manifest = Path(manifest_dir) / manifest.name
        staged_project = Path(project_dir) / project.name
        original_project = Path(project_dir) / "original.toml"
        shutil.copy2(project, original_project)
        staged_manifest.write_bytes(manifest_text.encode("utf-8"))
        staged_manifest.chmod(stat.S_IMODE(manifest.stat().st_mode))
        staged_project.write_bytes(project_text.encode("utf-8"))
        staged_project.chmod(stat.S_IMODE(project.stat().st_mode))
        staged_project.replace(project)
        try:
            staged_manifest.replace(manifest)
        except OSError:
            original_project.replace(project)
            raise


def update_dependency(root: Path, version: str, *, prepare_lock: bool = False) -> bool:
    """Update the declarations without downgrading and optionally prepare a stale lock for repair."""
    target_parts = _version_parts(version)
    manifest_path = root / "custom_components" / "frank_energie" / "manifest.json"
    pyproject_path = root / "pyproject.toml"
    manifest_text = manifest_path.read_bytes().decode("utf-8")
    pyproject_text = pyproject_path.read_bytes().decode("utf-8")
    current_version = _current_version(manifest_text, pyproject_text)
    if _version_parts(current_version) > target_parts:
        return False
    if current_version == version and (not prepare_lock or _locked_versions(root) == [version]):
        return False

    old_pin = f'"{PACKAGE_NAME}=={current_version}"'
    existing_constraint = POETRY_PATTERN.search(pyproject_text)
    if existing_constraint is None:
        raise ValueError("Cannot locate the existing Poetry dependency")
    if manifest_text.count(old_pin) != 1:
        raise ValueError("Cannot identify a unique library dependency in both configuration files")

    updated_manifest = manifest_text.replace(old_pin, f'"{PACKAGE_NAME}=={version}"', 1)
    start, end = existing_constraint.span("constraint")
    updated_pyproject = f"{pyproject_text[:start]}=={version}{pyproject_text[end:]}"
    if _current_version(updated_manifest, updated_pyproject) != version:
        raise ValueError("Dependency declarations do not agree after the update")

    if (updated_manifest, updated_pyproject) != (manifest_text, pyproject_text):
        _replace_declarations(manifest_path, updated_manifest, pyproject_path, updated_pyproject)
    return True


def main(argv: list[str] | None = None) -> int:
    """Update a checked-out integration and report whether anything changed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="Home Assistant integration repository checkout")
    parser.add_argument("--version", required=True, help="Published stable library version")
    lock_action = parser.add_mutually_exclusive_group()
    lock_action.add_argument("--prepare-lock", action="store_true", help="Prepare a dependency or lockfile update")
    lock_action.add_argument("--verify-lock", action="store_true", help="Verify the exact locked library version")
    arguments = parser.parse_args(argv)

    try:
        if arguments.verify_lock:
            versions = _locked_versions(arguments.root)
            if versions != [arguments.version]:
                raise ValueError(f"Unexpected library version in Poetry lockfile: {versions}")
            return 0
        changed = update_dependency(arguments.root, arguments.version, prepare_lock=arguments.prepare_lock)
    except (ValueError, OSError) as error:
        parser.error(f"Cannot safely synchronize the Home Assistant dependency: {error}")
    print("updated" if changed else "up-to-date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
