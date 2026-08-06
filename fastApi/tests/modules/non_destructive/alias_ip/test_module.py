"""Tests no destructivos de alias_ip. / Non-destructive alias_ip tests."""
from __future__ import annotations

import json
from pathlib import Path

from common.runner import call, require

ALIAS_IP = Path("/var/lib/praesidium/candidate/alias_ip.json")


def _read_alias_ip() -> dict:
    # ES: Lee alias_ip.json para elegir UUIDs reales sin modificar estado.
    # EN: Read alias_ip.json to pick real UUIDs without modifying state.
    return json.loads(ALIAS_IP.read_text(encoding="utf-8"))


def _first_uuid(section: str) -> str | None:
    # ES: Devuelve el primer UUID disponible de una sección.
    # EN: Return the first available UUID for a section.
    data = _read_alias_ip()
    values = data.get(section, {})
    if isinstance(values, dict):
        for uuid in values:
            return uuid
    return None


def run(ctx) -> None:
    # ES: Ejecuta comprobaciones read-only de alias_ip para viewer/admin.
    # EN: Execute read-only alias_ip checks for viewer/admin.
    ctx.log("=== ALIAS_IP NON-DESTRUCTIVE ===")

    status, payload = call(ctx, "status", "GET", "/api/v1/alias-ip/status")
    require(ctx, status == 200, "status endpoint returns 200", f"status endpoint returned {status}")

    status, payload = call(ctx, "list addresses", "GET", "/api/v1/alias-ip/addresses")
    require(ctx, status == 200 and isinstance(payload, dict) and payload.get("section") == "alias_address", "addresses list is readable", "addresses list failed")

    status, payload = call(ctx, "list address groups", "GET", "/api/v1/alias-ip/address-groups")
    require(ctx, status == 200 and isinstance(payload, dict) and payload.get("section") == "alias_addr_group", "address groups list is readable", "address groups list failed")

    address_uuid = _first_uuid("alias_address")
    if address_uuid:
        status, payload = call(ctx, "translate address", "POST", "/api/v1/alias-ip/translate", {"UUID": address_uuid})
        require(ctx, status == 200 and payload.get("section") == "alias_address", "address translate works", "address translate failed")
        status, payload = call(ctx, "deep translate address", "POST", "/api/v1/alias-ip/deep_translate", {"UUID": address_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content"), list), "address deep_translate works", "address deep_translate failed")
        status, payload = call(ctx, "deep translate sanitized address", "POST", "/api/v1/alias-ip/deep_translate_sanitized", {"UUID": address_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content_sanitized"), list), "address deep_translate_sanitized works", "address deep_translate_sanitized failed")

    group_uuid = _first_uuid("alias_addr_group")
    if group_uuid:
        status, payload = call(ctx, "translate address group", "POST", "/api/v1/alias-ip/translate", {"UUID": group_uuid})
        require(ctx, status == 200 and payload.get("section") == "alias_addr_group", "address group translate works", "address group translate failed")
        status, payload = call(ctx, "deep translate address group", "POST", "/api/v1/alias-ip/deep_translate", {"UUID": group_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content"), list), "address group deep_translate works", "address group deep_translate failed")
        status, payload = call(ctx, "deep translate sanitized address group", "POST", "/api/v1/alias-ip/deep_translate_sanitized", {"UUID": group_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content_sanitized"), list), "address group deep_translate_sanitized works", "address group deep_translate_sanitized failed")
