#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Filename: test_query.py
# Project: python-frank-energie
# Created Date: 2025-4-4

"""
Test script to query the Frank Energie API for electricity and gas market prices.

This module provides a simple way to verify that the API connection is working
and to retrieve current market prices for debugging or testing purposes.
"""

from __future__ import annotations
from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timedelta

from python_frank_energie import FrankEnergie

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
_LOGGER = logging.getLogger(__name__)


async def execute_query():
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
    current_date = datetime.now().date()
    tomorrow = current_date + timedelta(days=1)

    try:
        async with FrankEnergie() as frank_energie:
            _LOGGER.info("Fetching market prices for date range %s to %s", current_date, tomorrow)
            market_prices = await frank_energie.prices(current_date, tomorrow)

            if not market_prices:
                _LOGGER.warning("No market prices available for the given date range.")
                return 1  # No data found

            electricity_prices = market_prices.electricity
            gas_prices = market_prices.gas

            if not electricity_prices and not gas_prices:
                _LOGGER.warning("No prices available.")
                return 1

            if not electricity_prices:
                _LOGGER.warning("No electricity prices available.")
            if not gas_prices:
                _LOGGER.warning("No gas prices available.")

            # Log electricity prices
            _LOGGER.info("Electricity Prices:")
            if hasattr(electricity_prices, 'all') and electricity_prices.all:
                for price in electricity_prices.all:
                    _LOGGER.info(
                        "From: %s, Till: %s, Market Price: %.4f, Total: %.4f",
                        price.date_from, price.date_till, price.market_price, price.total
                    )
            else:
                _LOGGER.warning("No electricity price details available.")

            # Log gas prices
            _LOGGER.info("Gas Prices:")
            if hasattr(gas_prices, 'all') and gas_prices.all:
                for price in gas_prices.all:
                    _LOGGER.info(
                        "From: %s, Till: %s, Market Price: %.4f, Total: %.4f",
                        price.date_from, price.date_till, price.market_price, price.total
                    )
            else:
                _LOGGER.warning("No gas price details available.")

            return 0  # Success

    except ConnectionError as e:
        _LOGGER.error("Connection error: %s", e)
        return 2
    except ValueError as e:
        _LOGGER.error("Value error: %s", e)
        return 3
    except KeyboardInterrupt:
        _LOGGER.warning("Process interrupted by user.")
        return 4
    except Exception as e:
        _LOGGER.error("Unexpected error: %s", e)
        return 5


if __name__ == "__main__":
    sys.exit(asyncio.run(execute_query()))
