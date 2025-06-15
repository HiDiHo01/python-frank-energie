import asyncio
import logging
import os

from dotenv import load_dotenv
from python_frank_energie import FrankEnergie
from python_frank_energie.exceptions import AuthException

load_dotenv()

logging.basicConfig(level=logging.INFO)
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


if __name__ == "__main__":
    asyncio.run(main())
