#!/usr/bin/env python3
# Filename: test_query.py
# Project: python-frank-energie
# Created Date: 2025-4-4

"""
Test script to query the Frank Energie API for electricity and gas market prices.

This module provides a simple way to verify that the API connection is working
and to retrieve current market prices for debugging or testing purposes.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, date, datetime, timedelta

from python_frank_energie import FrankEnergie

# Configure logging
# logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s [Line %(lineno)d]")
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s [Line %(lineno)d]")
_LOGGER = logging.getLogger(__name__)


async def execute_query() -> int:
    """
    Execute a query to retrieve market prices for electricity and gas from the Frank Energie API.

    This function initializes the Frank Energie client, retrieves market prices for the next day,
    and prints the results to the console. It handles exceptions and provides appropriate exit codes.

    Args:
        None

    Returns:
        int: Exit code indicating the result of the query:
            0 - Success
            1 - No market prices available
            2 - Connection error occurred
            3 - Value error occurred
            4 - Process interrupted by user
            5 - Unexpected error occurred
    """
    current_date: date = datetime.now(UTC).date()
    tomorrow: date = current_date + timedelta(days=1)

    _LOGGER.info(
        "Fetching market prices for date range %s to %s",
        current_date,
        tomorrow,
    )

    try:
        async with FrankEnergie() as frank_energie:
            market_prices = await frank_energie.prices(
                current_date,
                tomorrow,
                "PT15M",
            )

        if market_prices is None:
            _LOGGER.warning("No market prices returned.")
            return 1

        electricity_prices = market_prices.electricity
        gas_prices = market_prices.gas

        electricity_entries = electricity_prices.all if electricity_prices else []
        gas_entries = gas_prices.all if gas_prices else []

        if not electricity_entries and not gas_entries:
            _LOGGER.warning("No electricity or gas prices available.")
            return 1

        _LOGGER.info(
            "Retrieved %s electricity prices and %s gas prices",
            len(electricity_entries),
            len(gas_entries),
        )

        if electricity_entries:
            _LOGGER.debug("Electricity prices:")

            for price in electricity_entries:
                _LOGGER.debug(
                    "From=%s Till=%s Market=%.4f Total=%.4f",
                    price.date_from,
                    price.date_till,
                    price.market_price,
                    price.total,
                )
        else:
            _LOGGER.warning("No electricity prices available.")
            return 1

        if gas_entries:
            _LOGGER.debug("Gas prices:")

            for price in gas_entries:
                _LOGGER.debug(
                    "From=%s Till=%s Market=%.4f Total=%.4f",
                    price.date_from,
                    price.date_till,
                    price.market_price,
                    price.total,
                )
        else:
            _LOGGER.warning("No gas prices available.")
            return 1
        return 0

    except ConnectionError:
        _LOGGER.exception("Connection error while querying Frank Energie")
        return 2

    except ValueError:
        _LOGGER.exception("Invalid data received from Frank Energie")
        return 3

    except asyncio.CancelledError:
        raise

    except KeyboardInterrupt:
        _LOGGER.warning("Process interrupted by user")
        return 4

    except Exception:
        _LOGGER.exception("Unexpected error while querying Frank Energie")
        return 5


async def main() -> int:
    """
    Run the query script.

    Returns:
        Process exit code.
    """
    return await execute_query()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
