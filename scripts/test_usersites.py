import asyncio
import logging
import os

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
        logger.info("User %s is logged in!", EMAIL)
        logger.debug("FrankEnergie instance: %s", frank)
        logger.debug("FrankEnergie instance attributes: %s", frank.__dict__)
        logger.debug("FrankEnergie instance methods: %s", frank.__dir__())
        logger.debug("Available methods and attributes: %s", dir(frank))
        logger.debug("FrankEnergie docstring: %s", frank.__doc__)

    if frank.is_authenticated:
        user_data = await frank.UserSites()
        logger.debug("User: %s", user_data)
        # delivery_sites = user_data.deliverySites
        delivery_sites = [site for site in user_data.deliverySites if site.status == "IN_DELIVERY"]
        if delivery_sites:
            site = delivery_sites[0]
            logger.info("Delivery Site Reference: %s", site.reference)
        else:
            logger.info("No delivery sites available.")

        await frank.close()

if __name__ == "__main__":
    asyncio.run(main())
