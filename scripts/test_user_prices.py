import asyncio
import logging
import os
from datetime import date, timedelta

from dotenv import load_dotenv
from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthException

load_dotenv()

logging.basicConfig(level=logging.INFO)  # Set logging level to INFO
# Set logging level to DEBUG for more detailed output
# logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

EMAIL: str | None = os.getenv("FRANK_ENERGIE_EMAIL")
PASSWORD: str | None = os.getenv("FRANK_ENERGIE_PASSWORD")


async def main() -> None:
    """
    Authenticate with Frank Energie API and log instance information.

    Raises:
        ValueError: If environment variables for login are not set.
    """
    if not EMAIL or not PASSWORD:
        raise ValueError("Missing FRANK_ENERGIE_EMAIL or FRANK_ENERGIE_PASSWORD in environment variables")

    frank = FrankEnergie()

    try:
        await frank.login(EMAIL, PASSWORD)
    except AuthException as e:
        logger.error("Authentication failed: %s", e)
        return
    finally:
        await frank.close()

    if frank.is_authenticated:
        logger.debug("User %s is logged in!", EMAIL)
        logger.debug("FrankEnergie instance: %s", frank)
        logger.debug("FrankEnergie instance attributes: %s", frank.__dict__)
        logger.debug("FrankEnergie instance methods: %s", frank.__dir__())
        logger.debug("Available methods and attributes: %s", dir(frank))
        logger.debug("FrankEnergie docstring: %s", frank.__doc__)

        user_data = await frank.UserSites()
        logger.debug("User: %s", user_data)
        # delivery_sites = user_data.deliverySites
        delivery_sites = [site for site in user_data.deliverySites if site.status == "IN_DELIVERY"]
        if delivery_sites:
            site = delivery_sites[0]
            logger.debug("Delivery Site Reference: %s", site.reference)
        else:
            logger.info("No delivery sites available.")

        user_prices = await frank.user_prices(date.today(), site.reference, date.today() + timedelta(days=2))
        # logger.info("energy_type: ", user_prices.energy_type)
        logger.debug(user_prices)
        if user_prices.electricity:
            electricity_prices = user_prices.electricity
        if user_prices.gas:
            gas_prices = user_prices.gas

    # prices_today = prices or user_prices
    prices_today = user_prices
    # logger.info("energy_type: ", prices_today.energy_type)

    # Access electricity price data
    if electricity_prices.all:
        logger.info("Electricity prices:")
        logger.info(len(electricity_prices.all))
        logger.info(electricity_prices)

    # Access gas price data
    if gas_prices.all:
        logger.info("Gas prices:")
        logger.info(len(gas_prices.all))
        logger.info(gas_prices)

    await frank.close()

if __name__ == "__main__":
    asyncio.run(main())
