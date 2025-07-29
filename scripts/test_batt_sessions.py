import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from dotenv import load_dotenv
from python_frank_energie import FrankEnergie

logging.basicConfig(level=logging.NOTSET, format="%(asctime)s - %(levelname)s - %(message)s")
# logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
load_dotenv()


async def analyze_smart_batteries(api: FrankEnergie) -> None:
    """Fetch and analyze all available smart battery data, including trading details."""
    logging.info("🔹 Fetching Smart Batteries...")
    try:
        batteries = await api.smart_batteries()
        logging.debug(f"Smart batteries data: {batteries}")
    except Exception as e:
        logging.error(f"⚠️ Could not fetch smart batteries: {e}")
        return

    if not batteries or not hasattr(batteries, 'smart_batteries'):
        logging.warning("❌ No smart batteries found.")
        return

    if not batteries or not batteries.smart_batteries:
        logging.warning("❌ No smart batteries found.")
        return

    for battery in batteries.smart_batteries:
        device_id = battery.id
        logging.info("\n🔋 **Battery Overview**")
        logging.info(f"📛 ID: {device_id}")
        logging.info(f"🏷 Brand: {battery.brand}")
        logging.info(f"🔋 Capacity: {battery.capacity} kWh")
        logging.info(f"⚡ Max Charge Power: {battery.max_charge_power} kW")
        logging.info(f"⚡ Max Discharge Power: {battery.max_discharge_power} kW")
        logging.info(f"🏭 Provider: {battery.provider}")
        logging.info(f"🕒 Created At: {battery.created_at}")
        logging.info(f"🔄 Last Updated: {battery.updated_at}")

        try:
            battery_details = await api.smart_battery_details(device_id)
            logging.debug(f"🔹 Battery details data: {battery_details}")
        except Exception as e:
            logging.error(f"⚠️ Could not fetch battery details for {device_id}: {e}")
            continue

        # logging.info(f"🔄 battery_mode: {battery_details.smart_battery.settings.battery_mode}")
        # logging.info(f"🔄 imbalance_trading_strategy: {battery_details.settings.imbalance_trading_strategy}")
        # logging.info(f"🔄 self_consumption_trading_allowed: {battery_details.settings.self_consumption_trading_allowed}")

        # Define time period (last 7 days)
        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=1)

        logging.info("🔹 Fetching Battery Trading Sessions...")
        try:
            sessions = await api.smart_battery_sessions(device_id, start_date, end_date)
            logging.debug(f"🔹 Battery sessions data: {sessions}")
        except Exception as e:
            logging.error(f"⚠️ Could not fetch battery sessions for {device_id}: {e}")
            continue

        if not sessions:
            logging.warning("⚠️ No session data available.")
            continue

        logging.info(f"💰 **Total Trading Profit (Last 7 Days):** €{sessions.period_total_result:.2f}")
        logging.info(f"📊 **Total Imbalance Result:** €{sessions.period_imbalance_result:.2f}")
        logging.info(f"📉 **Total EPEX Result:** €{sessions.period_epex_result:.2f}")
        logging.info(f"💡 **Total Trade Index:** {sessions.period_trade_index:.4f}")

        highest_profit_session = max(
            sessions.sessions, key=lambda s: getattr(s, "result", 0), default=None
        )
        if highest_profit_session:
            logging.info(
                f"🔥 **Best Trading Session:** {highest_profit_session.date} | Profit: €{highest_profit_session.trading_result:.2f}"
            )

        trading_profits = [getattr(s, "result", 0) for s in sessions.sessions]
        avg_trading_profit = sum(trading_profits) / len(trading_profits) if trading_profits else 0
        logging.info(f"📈 **Average Trading Profit per Session:** €{avg_trading_profit:.2f}")

        logging.info("\n📜 **Detailed Session Data:**")
        for session in sessions.sessions:
            log_session_data(session)

        logging.info("\n✅ Finished analysis for this battery.\n")


def log_session_data(session: Any) -> None:
    try:
        logging.info("\n----------------------------------")
        logging.info(f"📅 Date: {session.date}")
        logging.info(f"💰 Trading Profit: €{session.result:.2f}")
        logging.info(f"📈 Cumulative Profit: €{session.cumulative_result:.2f}")
    except AttributeError as e:
        logging.error(f"⚠️ Missing attribute in session: {e}")


async def main():
    """Main function loop."""
    EMAIL = os.getenv("FRANK_ENERGIE_EMAIL")
    PASSWORD = os.getenv("FRANK_ENERGIE_PASSWORD")

    logging.info("🔹 Starting the main function...")
    try:
        async with FrankEnergie() as api:
            await api.login(EMAIL, PASSWORD)
            await analyze_smart_batteries(api)

    except Exception as e:
        logging.exception(f"\nAn unexpected error occurred: {e}")


if __name__ == "__main__":
    asyncio.run(main())
