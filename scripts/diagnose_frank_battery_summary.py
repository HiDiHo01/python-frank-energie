#!/usr/bin/env python3
"""Inspect all seven SmartBatterySummary fields from PR #288 without the SDK.

Python 3.12+. Standard library only. No introspection, retries or device writes.
Credentials and device identifiers are never printed.
"""

import argparse
import asyncio
import http.client
import json
import math
import re
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path

API_HOST = "frank-graphql-prod.graphcdn.app"
TIMEOUT = 30
MAX_BYTES = 512 * 1024
FIELDS = (
    "activityStatus", "gridCongestionStatus", "lastKnownStateOfCharge",
    "lastKnownStatus", "lastUpdate", "status", "totalResult",
)
STATUS_FIELDS = frozenset({"activityStatus", "gridCongestionStatus", "lastKnownStatus", "status"})
SAFE_WORDS = frozenset("ACTIVE BALANCING BATTERY CHARGE CHARGING CONGESTION CONNECTED CONNECTING DISCONNECTED CONNECTION CONSUMPTION DATA DISCHARGE DISCHARGING EMPTY ENROLLED EPEX ERROR FIFTEEN FULL GRID HOME IDLE IMBALANCE IMBALANCES INTRADAY MAINTENANCE MIXED NOT OFFLINE ONLINE PENDING PERCENT PERCENTAGE PRICE PV SEPARATE SELF SMART SOLAR STANDBY STATUS TRADING UNKNOWN UNRELIABLE".split())
LOGIN = """mutation Login($email: String!, $password: String!) {
    login(email: $email, password: $password) { authToken }
}"""
INVENTORY = "query SmartBatteries { smartBatteries { id provider } }"
SUMMARY = """query SmartBattery($deviceId: String!) {
    smartBatterySummary(deviceId: $deviceId) {
        activityStatus
        gridCongestionStatus
        lastKnownStateOfCharge
        lastKnownStatus
        lastUpdate
        status
        totalResult
    }
}"""


class DiagnosticError(Exception):
    """Represent a diagnostic failure safe to display publicly."""


def load_credentials(path: Path) -> tuple[str, str]:
    """Read existing plain or quoted dotenv assignments without executing them."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        raise DiagnosticError("Cannot read .env; use --env-file with its existing path.") from None
    values: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        entry = line.strip().removeprefix("export ").strip()
        if not entry or entry.startswith("#"):
            continue
        key, separator, value = entry.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key.strip()):
            raise DiagnosticError(f"Invalid .env assignment on line {number}.")
        value = value.strip()
        if value.startswith(("'", '"')):
            end = value.rfind(value[0])
            if end == 0 or (value[end + 1:].strip() and not value[end + 1:].strip().startswith("#")):
                raise DiagnosticError(f"Invalid quoted .env value on line {number}.")
            value = value[1:end]
        values[key.strip()] = value
    email = values.get("FRANK_EMAIL") or values.get("FRANK_ENERGIE_EMAIL") or values.get("FRANK_ENERGIE_USERNAME")
    password = values.get("FRANK_PASSWORD") or values.get("FRANK_ENERGIE_PASSWORD")
    if not email or "@" not in email or any(char.isspace() for char in email) or not password:
        raise DiagnosticError("Set valid FRANK_EMAIL and FRANK_PASSWORD (or FRANK_ENERGIE_* equivalents) in .env.")
    return email, password


def request(operation: str, query: str, variables: dict[str, str], token: str | None = None) -> dict[str, object]:
    """Execute one HTTPS GraphQL request without exposing upstream errors."""
    headers = {
        "Accept": "application/json", "Content-Type": "application/json",
        "x-graphql-client-version": "4.35.0", "x-graphql-client-name": "frank-app",
        "x-graphql-client-os": "ios/26.0.1", "skip-graphcdn": "1",
        "User-Agent": "FrankEnergieBatterySummaryDiagnostic/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = json.dumps({"operationName": operation, "query": query, "variables": variables}).encode()
    connection = http.client.HTTPSConnection(API_HOST, timeout=TIMEOUT, context=ssl.create_default_context())
    try:
        connection.request("POST", "/", body=payload, headers=headers)
        response = connection.getresponse()
        status_code = response.status
        content = response.read(MAX_BYTES + 1)
    except (OSError, http.client.HTTPException, ValueError):
        raise DiagnosticError(f"{operation}: connection/TLS failure or invalid request.") from None
    finally:
        connection.close()
    if status_code != 200:
        raise DiagnosticError(f"{operation}: HTTP {status_code}; no retry attempted.")
    if len(content) > MAX_BYTES:
        raise DiagnosticError(f"{operation}: response exceeds size limit.")
    try:
        result = json.loads(content)
    except (ValueError, UnicodeError):
        raise DiagnosticError(f"{operation}: invalid JSON.") from None
    if not isinstance(result, dict) or result.get("errors") or not isinstance(result.get("data"), dict):
        raise DiagnosticError(f"{operation}: GraphQL error or invalid data; upstream details hidden.")
    return result["data"]


def safe_field(field: str, value: object) -> object:
    """Preserve null, empty and legitimate values; redact unexpected private text."""
    if value is None:
        return None
    if field in STATUS_FIELDS:
        if not isinstance(value, str):
            return "<invalid-type>"
        if not value:
            return ""
        if len(value) <= 64 and value.isascii() and all(part in SAFE_WORDS for part in value.upper().split("_")):
            return value
        return "<redacted>"
    if field == "lastUpdate":
        if isinstance(value, str) and len(value) <= 48:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is not None:
                    return value
            except ValueError:
                pass
        return "<invalid-timestamp>"
    if type(value) in (int, float):
        try:
            if math.isfinite(value):
                return value
        except OverflowError:
            pass
    return "<invalid-type-or-number>"


def summarize(data: dict[str, object]) -> dict[str, object]:
    """Expose the seven fields and distinguish absent fields from explicit nulls."""
    if "smartBatterySummary" not in data:
        return {"summary_state": "missing"}
    summary = data["smartBatterySummary"]
    if summary is None:
        return {"smartBatterySummary": None, "summary_state": "explicit_null"}
    if not isinstance(summary, dict):
        return {"summary_state": "invalid_type"}
    return {
        "smartBatterySummary": {field: safe_field(field, summary[field]) for field in FIELDS if field in summary},
        "missing_fields": [field for field in FIELDS if field not in summary],
        "null_fields": [field for field in FIELDS if field in summary and summary[field] is None],
    }


async def run(env_file: Path) -> dict[str, object]:
    """Authenticate once and inspect every battery sequentially."""
    email, password = await asyncio.to_thread(load_credentials, env_file)
    login = await asyncio.to_thread(request, "Login", LOGIN, {"email": email, "password": password})
    auth = login.get("login")
    token = auth.get("authToken") if isinstance(auth, dict) else None
    if not isinstance(token, str) or not token or any(char.isspace() for char in token):
        raise DiagnosticError("Login returned no usable token.")
    inventory = await asyncio.to_thread(request, "SmartBatteries", INVENTORY, {}, token)
    batteries = inventory.get("smartBatteries")
    if not isinstance(batteries, list) or len(batteries) > 25:
        raise DiagnosticError("Invalid battery inventory or more than 25 batteries; stopped.")
    results: list[dict[str, object]] = []
    for index, battery in enumerate(batteries, 1):
        device_id = battery.get("id") if isinstance(battery, dict) else None
        if not isinstance(device_id, str) or not device_id:
            raise DiagnosticError("Inventory contains an invalid device ID.")
        if index > 1:
            await asyncio.sleep(0.5)
        provider = battery.get("provider")
        record: dict[str, object] = {"battery_number": index, "provider": provider if provider in ("SESSY", "ANKER", "HYXI") else "OTHER"}
        try:
            data = await asyncio.to_thread(request, "SmartBattery", SUMMARY, {"deviceId": device_id}, token)
            record.update(summarize(data))
        except DiagnosticError as error:
            record["error"] = str(error)
            results.append(record)
            break  # Stop on a request error, including rate limiting.
        results.append(record)
    return {"captured_at_utc": datetime.now(UTC).isoformat(), "battery_count": len(batteries), "batteries": results}


def main() -> int:
    """Read CLI settings and print a privacy-filtered JSON report."""
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parent / ".env"
    if not default.is_file():
        default = Path.cwd() / ".env"
    parser.add_argument("--env-file", type=Path, default=default)
    options = parser.parse_args()
    try:
        report = asyncio.run(run(options.env_file))
    except DiagnosticError as error:
        print(f"Diagnostic failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    return int(any("error" in item for item in report["batteries"]))


if __name__ == "__main__":
    sys.exit(main())
