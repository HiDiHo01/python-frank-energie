#!/usr/bin/env python3
"""Diagnose raw Frank Energie Smart Battery status values without the SDK.

Read credentials from a local .env file; send only the documented Login,
SmartBatteries and SmartBattery GraphQL operations. The program never prints
credentials, tokens, internal battery IDs, GraphQL error text or raw responses.

Python 3.12+; standard library only. No GraphQL introspection is performed.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

API_HOST = "frank-graphql-prod.graphcdn.app"
API_PATH = "/"
MAX_RESPONSE_BYTES = 512 * 1024
TIMEOUT_SECONDS = 30
REQUEST_PAUSE_SECONDS = 0.5

# Copy of the recognized status *values* from python-frank-energie's
# SmartBatteryStatus enum at the time this diagnostic was written. No SDK import.
KNOWN_STATUSES = frozenset(
    {
        "status_charging",
        "status_discharging",
        "status_idle",
        "status_unreliable_data",
        "status_offline",
        "status_standby",
        "separate_imbalances",
        "idle_full",
        "idle_price",
        "discharge_self_consumption",
        "discharge_imbalance",
        "charge_imbalance",
        "discharge_intraday",
        "charge_intraday",
        "idle_intraday",
        "charge_epex",
        "discharge_epex",
        "idle_epex",
        "discharge_congestion",
        "charge_congestion",
        "discharge_self_consumption_mixed",
        "idle_congestion",
        "idle_empty",
        "idle_fifteen_percent",
        "idle_fifteen_percentage",
        "charge_self_consumption",
        "charge_self_consumption_mixed",
        "status_maintenance",
        "status_error",
        "discharge_smart_home",
        "charge_smart_home",
        "idle_smart_home",
    }
)

# Only fixed status-related words may be displayed verbatim. An arbitrary
# upstream string could contain an identifier; it will instead be redacted.
SAFE_STATUS_WORDS = frozenset(
    {
        "ACTIVE", "BALANCING", "BATTERY", "CHARGE", "CHARGING", "CONGESTION",
        "CONSUMPTION", "DATA", "DISCHARGE", "DISCHARGING", "EMPTY", "EPEX",
        "ERROR", "FIFTEEN", "FULL", "GRID", "HOME", "IDLE", "IMBALANCE",
        "IMBALANCES", "INTRADAY", "MAINTENANCE", "MIXED", "OFFLINE",
        "ONLINE", "PERCENT", "PERCENTAGE", "PRICE", "PV", "SEPARATE",
        "SELF", "SMART", "SOLAR", "STANDBY", "STATUS", "TRADING",
        "UNKNOWN", "UNRELIABLE",
    }
)
KNOWN_MODES = frozenset(
    {"congestion", "imbalance_trading", "self_consumption", "self_consumption_mix", "trading", "unknown"}
)
KNOWN_ALGORITHMS = frozenset({"t1", "t2", "t3", "unknown"})
KNOWN_PROVIDERS = frozenset({"ANKER", "SESSY"})
ENV_KEY_PATTERN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z", re.ASCII)

LOGIN_QUERY = """
mutation Login($email: String!, $password: String!) {
    login(email: $email, password: $password) {
        authToken
    }
}
"""
BATTERIES_QUERY = """
query SmartBatteries {
    smartBatteries {
        id
        provider
    }
}
"""
BATTERY_QUERY = """
query SmartBattery($deviceId: String!) {
    smartBattery(deviceId: $deviceId) {
        settings {
            batteryMode
            tradingAlgorithm
        }
    }
    smartBatterySummary(deviceId: $deviceId) {
        lastKnownStatus
        lastUpdate
    }
}
"""


class DiagnosticError(Exception):
    """Describe a sanitized diagnostic failure without private data."""


def _load_dotenv(file_path: Path) -> dict[str, str]:
    """Load plain and quoted KEY=VALUE lines from a local .env file.

    Inline comments after an unquoted value are not interpreted: quoting is
    recommended when a password contains spaces or a hash character.
    """
    if not file_path.is_file():
        raise DiagnosticError("No .env file found. Create it beside the script or use --env-file.")

    values: dict[str, str] = {}
    try:
        lines = file_path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        raise DiagnosticError("Cannot read the .env file as UTF-8; check its path and encoding.") from None

    for line_number, line in enumerate(lines, 1):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        if stripped_line.startswith("export "):
            stripped_line = stripped_line[7:].lstrip()
        if "=" not in stripped_line:
            raise DiagnosticError(f"Malformed .env assignment on line {line_number}.")

        key, raw_value = stripped_line.split("=", 1)
        key = key.strip()
        if not ENV_KEY_PATTERN.fullmatch(key):
            raise DiagnosticError(f"Invalid .env variable name on line {line_number}.")

        value = raw_value.strip()
        if value.startswith(("'", '"')):
            quote_char = value[0]
            closing_quote = value.rfind(quote_char)
            if closing_quote == 0:
                raise DiagnosticError(f"Unclosed quoted .env value on line {line_number}.")
            remainder = value[closing_quote + 1 :].strip()
            if remainder and not remainder.startswith("#"):
                raise DiagnosticError(f"Unexpected text after a quoted .env value on line {line_number}.")
            value = value[1:closing_quote]

        values[key] = value

    return values


def _get_credentials(values: dict[str, str]) -> tuple[str, str]:
    """Retrieve the two supported pairs of Frank Energie .env credentials."""
    email = values.get("FRANK_EMAIL") or values.get("FRANK_ENERGIE_EMAIL") or values.get("FRANK_ENERGIE_USERNAME")
    password = values.get("FRANK_PASSWORD") or values.get("FRANK_ENERGIE_PASSWORD")
    if not email or not password:
        raise DiagnosticError(
            "Missing credentials in .env. Set FRANK_EMAIL and FRANK_PASSWORD "
            "(or FRANK_ENERGIE_EMAIL/FRANK_ENERGIE_USERNAME and FRANK_ENERGIE_PASSWORD)."
        )
    if "@" not in email or any(character.isspace() for character in email):
        raise DiagnosticError("The Frank Energie email address in .env is invalid.")
    return email, password


def _graphql_request(
    operation_name: str,
    query: str,
    variables: dict[str, str] | None = None,
    *,
    bearer_token: str | None = None,
) -> dict[str, Any]:
    """Send one verified GraphQL operation over authenticated HTTPS.

    HTTP and GraphQL error payloads are intentionally never emitted because
    upstream error messages can contain credentials or account information.
    Automatic retries are disabled to avoid amplifying rate limiting.
    """
    payload = json.dumps(
        {"operationName": operation_name, "query": query, "variables": variables or {}},
        ensure_ascii=True,
    ).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-graphql-client-version": "4.35.0",
        "x-graphql-client-name": "frank-app",
        "x-graphql-client-os": "ios/26.0.1",
        "skip-graphcdn": "1",
        "User-Agent": "FrankEnergieBatteryStatusDiagnostic/1.0",
    }
    if bearer_token is not None:
        headers["Authorization"] = f"Bearer {bearer_token}"

    connection = http.client.HTTPSConnection(
        API_HOST,
        timeout=TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )
    try:
        connection.request("POST", API_PATH, body=payload, headers=headers)
        response = connection.getresponse()
        status_code = response.status
        content = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException, TimeoutError):
        raise DiagnosticError(f"Connection or TLS failure during {operation_name} (request details hidden).") from None
    finally:
        connection.close()

    if status_code == 429:
        raise DiagnosticError(f"{operation_name} was rate limited (HTTP 429); no automatic retry was attempted.")
    if status_code in (401, 403):
        raise DiagnosticError(f"{operation_name} was rejected (HTTP {status_code}); check your credentials.")
    if status_code != 200:
        raise DiagnosticError(f"{operation_name} failed with HTTP {status_code}; response hidden.")
    if len(content) > MAX_RESPONSE_BYTES:
        raise DiagnosticError(f"{operation_name} returned an unexpectedly large response.")

    try:
        result = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise DiagnosticError(f"{operation_name} returned invalid JSON; response hidden.") from None
    if not isinstance(result, dict):
        raise DiagnosticError(f"{operation_name} returned a non-object response.")

    errors = result.get("errors")
    if errors is not None and not isinstance(errors, list):
        raise DiagnosticError(f"{operation_name} returned a malformed GraphQL error container.")
    if errors:
        raise DiagnosticError(f"{operation_name} returned {len(errors)} GraphQL error(s); error text hidden.")

    data = result.get("data")
    if not isinstance(data, dict):
        raise DiagnosticError(f"{operation_name} returned no valid data object.")
    return data


def _safe_status(raw_status: object) -> str:
    """Display only a status composed of known non-identifying vocabulary."""
    if not isinstance(raw_status, str):
        return "<not-a-string>"
    parts = raw_status.upper().split("_")
    if (
        0 < len(raw_status) <= 64
        and raw_status.isascii()
        and len(parts) <= 5
        and all(part in SAFE_STATUS_WORDS for part in parts)
    ):
        return raw_status
    return "<redacted>"


def _classify_status(summary: dict[str, Any]) -> tuple[str, str]:
    """Classify an unconverted GraphQL lastKnownStatus field."""
    if "lastKnownStatus" not in summary:
        return "missing_field", "<missing>"
    raw_status = summary["lastKnownStatus"]
    if raw_status is None:
        return "explicit_null", "<null>"
    if not isinstance(raw_status, str):
        return "invalid_type", "<not-a-string>"
    if not raw_status:
        return "empty_string", "<empty>"
    if raw_status.casefold() == "unknown":
        return "explicit_unknown", _safe_status(raw_status)
    if raw_status.casefold() in KNOWN_STATUSES:
        return "recognized", _safe_status(raw_status)
    return "unrecognized", _safe_status(raw_status)


def _safe_timestamp(value: object) -> str:
    """Return a normalized UTC ISO timestamp, never arbitrary source text."""
    if not isinstance(value, str) or len(value) > 48:
        return "<missing-or-invalid>"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "<missing-or-invalid>"
    if parsed.tzinfo is None:
        return "<missing-or-invalid>"
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _safe_option(value: object, allowed_values: frozenset[str]) -> str:
    """Include only an explicitly allowlisted non-identifying API option."""
    if isinstance(value, str) and value.casefold() in allowed_values:
        return value.casefold()
    return "<unknown>"


def _diagnose_battery(index: int, battery: dict[str, Any], bearer_token: str) -> dict[str, object]:
    """Inspect one battery by ID without storing or displaying its ID."""
    battery_id = battery.get("id")
    if not isinstance(battery_id, str) or not battery_id:
        raise DiagnosticError("Inventory contained a battery with a missing or invalid device ID (ID hidden).")

    result = _graphql_request(
        "SmartBattery",
        BATTERY_QUERY,
        {"deviceId": battery_id},
        bearer_token=bearer_token,
    )
    summary = result.get("smartBatterySummary")
    if summary is None:
        status_kind, raw_status_display = "missing_summary", "<not-available>"
        timestamp = "<not-available>"
    elif isinstance(summary, dict):
        status_kind, raw_status_display = _classify_status(summary)
        timestamp = _safe_timestamp(summary.get("lastUpdate"))
    else:
        status_kind, raw_status_display = "invalid_summary", "<not-available>"
        timestamp = "<not-available>"

    details = result.get("smartBattery")
    settings = details.get("settings") if isinstance(details, dict) else None
    if not isinstance(settings, dict):
        settings = {}

    provider = battery.get("provider")
    provider_display = provider if isinstance(provider, str) and provider in KNOWN_PROVIDERS else "OTHER"
    return {
        "battery_number": index,
        "provider": provider_display,
        "battery_mode": _safe_option(settings.get("batteryMode"), KNOWN_MODES),
        "trading_algorithm": _safe_option(settings.get("tradingAlgorithm"), KNOWN_ALGORITHMS),
        "raw_lastKnownStatus": raw_status_display,
        "status_classification": status_kind,
        "summary_lastUpdate_utc": timestamp,
    }


def _run(env_file: Path) -> dict[str, object]:
    """Authenticate and inspect every battery using read-only queries."""
    email, password = _get_credentials(_load_dotenv(env_file))
    login_data = _graphql_request("Login", LOGIN_QUERY, {"email": email, "password": password})
    login_details = login_data.get("login")
    if not isinstance(login_details, dict):
        raise DiagnosticError("Login returned no authentication object; response hidden.")
    token = login_details.get("authToken")
    if not isinstance(token, str) or not token:
        raise DiagnosticError("Login returned no usable access token; response hidden.")

    inventory_data = _graphql_request("SmartBatteries", BATTERIES_QUERY, bearer_token=token)
    batteries = inventory_data.get("smartBatteries")
    if not isinstance(batteries, list):
        raise DiagnosticError("SmartBatteries did not return a battery list.")
    if len(batteries) > 25:
        raise DiagnosticError("More than 25 batteries returned; stopped to avoid excessive API calls.")

    results: list[dict[str, object]] = []
    for index, battery in enumerate(batteries, start=1):
        if not isinstance(battery, dict):
            raise DiagnosticError("SmartBatteries included a malformed battery record.")
        if index > 1:
            time.sleep(REQUEST_PAUSE_SECONDS)
        try:
            results.append(_diagnose_battery(index, battery, token))
        except DiagnosticError as err:
            # Our errors are carefully constructed without raw response data.
            results.append({"battery_number": index, "error": str(err)})

    return {
        "diagnostic": "Frank Energie raw smart battery statuses (no SDK)",
        "battery_count": len(batteries),
        "batteries": results,
        "note": (
            "Statuses are read before enum conversion. '<redacted>' means the raw value "
            "was not safe to display; IDs, credentials and API error bodies are never printed."
        ),
    }


def main() -> int:
    """Parse CLI options, run the diagnostic, and print sanitized JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(__file__).resolve().parent / ".env",
        help="Path to .env with Frank Energie credentials (default: beside this script)",
    )
    options = parser.parse_args()
    try:
        report = _run(options.env_file)
    except DiagnosticError as err:
        print(f"Diagnostic failed: {err}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
