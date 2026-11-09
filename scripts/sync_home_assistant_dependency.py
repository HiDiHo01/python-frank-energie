"""Synchronize the Frank Energie library requirement in a Home Assistant checkout."""

import argparse
import json
import re
import tomllib
from datetime import date
from pathlib import Path

PACKAGE_NAME = "python-frank-energie"
VERSION_PATTERN = re.compile(r"\d{4}\.\d{1,2}\.\d{1,2}\Z")
POETRY_PATTERN = re.compile(
    r"""^(?P<prefix>[ \t]*python-frank-energie[ \t]*=[ \t]*)(?P<quote>['"])(?P<operator>\^|==)(?P<version>\d{4}\.\d{1,2}\.\d{1,2})(?P=quote)(?P<suffix>[ \t]*(?:#.*)?)$""",
    re.MULTILINE,
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


def _current_version(manifest_text: str, pyproject_text: str) -> str:
    """Require exactly one matching manifest pin and Poetry dependency."""
    manifest = json.loads(manifest_text)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("requirements"), list):
        raise ValueError("Expected an integration manifest object with a requirements list")

    matching = [
        requirement
        for requirement in manifest["requirements"]
        if isinstance(requirement, str)
        and re.match(r"^python-frank-energie(?=$|[ \t]*(?:==|[!<>~=]))", requirement) is not None
    ]
    if len(matching) != 1 or re.fullmatch(r"python-frank-energie==([0-9]+\.[0-9]+\.[0-9]+)", matching[0]) is None:
        raise ValueError("Expected exactly one pinned python-frank-energie manifest requirement")

    version = matching[0].split("==", maxsplit=1)[1]
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


def update_dependency(root: Path, version: str) -> bool:
    """Update dependency declarations atomically after validation; never downgrade."""
    target_parts = _version_parts(version)
    manifest_path = root / "custom_components" / "frank_energie" / "manifest.json"
    pyproject_path = root / "pyproject.toml"
    manifest_text = manifest_path.read_text(encoding="utf-8")
    pyproject_text = pyproject_path.read_text(encoding="utf-8")
    current_version = _current_version(manifest_text, pyproject_text)
    if _version_parts(current_version) >= target_parts:
        return False

    old_pin = f'"{PACKAGE_NAME}=={current_version}"'
    existing_constraint = POETRY_PATTERN.search(pyproject_text)
    if existing_constraint is None:
        raise ValueError("Cannot locate the existing Poetry dependency")
    old_poetry = existing_constraint.group(0)
    if manifest_text.count(old_pin) != 1 or pyproject_text.count(old_poetry) != 1:
        raise ValueError("Cannot identify a unique library dependency in both configuration files")

    updated_manifest = manifest_text.replace(old_pin, f'"{PACKAGE_NAME}=={version}"', 1)
    quote = existing_constraint.group("quote")
    updated_poetry_line = (
        f'{existing_constraint.group("prefix")}{quote}=={version}{quote}{existing_constraint.group("suffix")}'
    )
    updated_pyproject = pyproject_text.replace(old_poetry, updated_poetry_line, 1)
    if _current_version(updated_manifest, updated_pyproject) != version:
        raise ValueError("Dependency declarations do not agree after the update")

    try:
        pyproject_path.write_text(updated_pyproject, encoding="utf-8")
        manifest_path.write_text(updated_manifest, encoding="utf-8")
    except OSError:
        pyproject_path.write_text(pyproject_text, encoding="utf-8")
        manifest_path.write_text(manifest_text, encoding="utf-8")
        raise
    return True


def main(argv: list[str] | None = None) -> int:
    """Update a checked-out integration and report whether anything changed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="Home Assistant integration repository checkout")
    parser.add_argument("--version", required=True, help="Published stable library version")
    arguments = parser.parse_args(argv)

    try:
        changed = update_dependency(arguments.root, arguments.version)
    except (ValueError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        parser.error(f"Cannot safely synchronize the Home Assistant dependency: {error}")
    print("updated" if changed else "up-to-date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
