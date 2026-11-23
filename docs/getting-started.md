---
title: Getting started
description: Install and make your first authenticated API request with python-frank-energie.
---

# Getting started

`python-frank-energie` is an asynchronous Python client for Frank Energie. It requires **Python 3.12 or newer**. API operations and available data depend on your account and enabled services.

## Install

```bash
python -m pip install python-frank-energie
```

Use a virtual environment. The PyPI package name uses hyphens; the import name uses underscores: `python_frank_energie`.

## Authentication

Store credentials in a secure local environment, never in source control. This example reads the connected smart-battery inventory and **prints only a count**, not identifiers or device details.

```python
import asyncio
import os

from python_frank_energie import FrankEnergie


async def main() -> None:
    """Authenticate and read the number of connected smart batteries."""
    email = os.environ.get("FRANK_EMAIL")
    password = os.environ.get("FRANK_PASSWORD")
    if not email or not password:
        raise ValueError("Set FRANK_EMAIL and FRANK_PASSWORD environment variables.")

    async with FrankEnergie() as client:
        await client.login(email, password)
        batteries = await client.smart_batteries()
        print("Connected smart batteries:", len(batteries.batteries))


if __name__ == "__main__":
    asyncio.run(main())
```

Run this only for an account with the corresponding Smart Battery feature enabled. Authentication, transport, and API errors are **not** silently treated as empty inventories.

## Understand the result

The SDK returns typed model objects, not arbitrary dictionaries. Provider responses can contain explicit `null` or missing optional fields: preserve those distinctions and never infer battery operations from unavailable data.

- [Authentication lifecycle](authentication.md) — tokens, renewal, and sessions
- [Rate limits](rate-limits.md) — `RateLimitException` and `retry_after`
- [Smart PV](smart-pv.md) and [Smart HVAC](smart-hvac.md) — supported feature APIs
- [Architecture](ARCHITECTURE.md) — transport, models, and public contracts

## Home Assistant

The SDK does not implement Home Assistant entities, periodic polling, or application credential persistence. Install the separate [Home Assistant integration](https://github.com/HiDiHo01/home-assistant-frank_energie) for those features.

## Troubleshooting

Do not log or share complete authenticated responses, access tokens, private addresses, site references, or device IDs. For unexpected statuses, compare sanitized raw status categories and response timestamps before assuming the provider returned a specific operating state.

Report reproducible problems at the [GitHub issue tracker](https://github.com/HiDiHo01/python-frank-energie/issues) using synthetic data.
