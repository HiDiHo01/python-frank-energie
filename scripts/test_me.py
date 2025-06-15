"""Run a test login and fetch user info from Frank Energie."""

import asyncio
import logging
import os

from dotenv import load_dotenv
from python_frank_energie import FrankEnergie

load_dotenv()

logging.basicConfig(level=logging.INFO)

EMAIL: str | None = os.getenv("FRANK_ENERGIE_EMAIL")
PASSWORD: str | None = os.getenv("FRANK_ENERGIE_PASSWORD")


async def main() -> None:
    """
    Main asynchronous function to authenticate and retrieve user info
    from the Frank Energie API.
    """
    if not EMAIL or not PASSWORD:
        logging.error("Missing environment variables: FRANK_ENERGIE_EMAIL or FRANK_ENERGIE_PASSWORD")
        return

    frank = FrankEnergie()

    try:
        await frank.login(EMAIL, PASSWORD)
        user_info = await frank.me()

        logging.info("-----------")
        logging.info("User info: %s", user_info)

    except Exception as err:
        logging.error("Error during API call: %s", err)

    finally:
        await frank.close()


if __name__ == "__main__":
    asyncio.run(main())
