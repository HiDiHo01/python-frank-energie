# AI Policy

## Purpose

This repository contains `python-frank-energie`, an asynchronous Python library for communicating with Frank Energie. The code is used as a reusable core for Home Assistant and related automation projects. Any AI-assisted contribution must preserve correctness, maintainability, and the repository's existing architectural conventions.

## Allowed use of AI

AI tools may be used to:

- draft or refactor code, documentation, tests, and changelogs
- explain existing code paths, bugs, and architecture
- propose improvements to type hints, docstrings, logging, validation, and async handling
- help with review comments, issue triage, and release notes

AI output is a starting point, not an authority. Human review is required before merge.

## Required human responsibility

Every change created with AI must be verified by a human contributor who understands the code being changed. The reviewer must confirm:

- the change is semantically correct
- the change fits the current architecture and public API
- the change does not weaken test coverage, security, or privacy
- the change does not introduce regressions in Home Assistant usage or library behavior

Do not merge code simply because it compiles or passes superficial checks.

## Prohibited use

Do not use AI to:

- make autonomous repository changes without a human reviewer
- invent API behavior, device behavior, or Frank Energie responses
- bypass tests, linting, or review requirements
- introduce secrets, credentials, tokens, or private user data into prompts
- add hidden logic, undocumented behavior, or speculative fallbacks without explicit review

## Code quality expectations for AI-assisted changes

AI-assisted code in this repository should follow the repository's style and engineering standards:

- modern Python syntax and type hints
- clear docstrings for modules, classes, methods, and public functions
- timezone-aware datetimes
- async-first design for network and I/O code
- structured logging with lazy `%` formatting
- descriptive validation and error messages
- consistent `snake_case`
- no unnecessary imports or dead code
- backward compatibility only when explicitly required

## Review requirements

A pull request that includes AI-assisted work should state that AI was used and summarize which parts were AI-generated or AI-refactored. The author must explain any non-obvious design decisions, especially around authentication, caching, price calculations, and coordinator behavior.

## Safety and privacy

This library communicates with a third-party energy service. Do not paste secrets, personal account data, or production tokens into AI prompts, issues, or pull requests. Any sample data used for testing must be sanitized.

## Maintenance

This policy should be updated when the repository architecture, test strategy, or contribution process changes.
