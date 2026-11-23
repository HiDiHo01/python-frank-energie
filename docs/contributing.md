---
title: Contributing
description: Repository development, quality checks, and GitHub Pages documentation build.
---

# Contributing

Contributions should preserve the public API and standalone-library architecture. Home Assistant-specific polling, caching, and entity lifecycles belong in the consuming integration.

## Development setup

```bash
git clone https://github.com/HiDiHo01/python-frank-energie.git
cd python-frank-energie
python -m pip install poetry
poetry install
```

## Quality checks

```bash
poetry run pytest tests
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy python_frank_energie
poetry check --lock
```

Read the repository's [AGENTS.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/AGENTS.md), [AI_POLICY.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/AI_POLICY.md), and [SKILLS.md](https://github.com/HiDiHo01/python-frank-energie/blob/main/SKILLS.md) before contributing. Protect backward compatibility; never include real credentials or device identifiers in fixtures. Human review is mandatory for AI-assisted pull requests.

## Documentation website

The website is built from the existing `docs/` Markdown files with a separately pinned Zensical generator. Build and preview locally:

```bash
python -m pip install -r requirements-docs.txt
zensical build --clean
zensical serve
```

Local preview defaults to `http://127.0.0.1:8000/`. GitHub Actions builds the site on pull requests and publishes only after changes land on `main`. Publication requires **Settings → Pages → Build and deployment → Source: GitHub Actions**.

## Request changes

File a [GitHub issue](https://github.com/HiDiHo01/python-frank-energie/issues) for defects or enhancements, then submit changes for review. Provider GraphQL fields must be independently verified; do not perform blocked schema introspection.
