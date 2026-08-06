"""Tests no destructivos de alias_services. / Non-destructive alias_services tests."""
from __future__ import annotations

import json
from pathlib import Path

from common.runner import call, require

ALIAS_SERVICES = Path("/var/lib/praesidium/candidate/alias_services.json")


def _read_alias_services() -> dict:
    # ES: Lee alias_services.json para elegir UUIDs reales sin modificar estado.
    # EN: Read alias_services.json to pick real UUIDs without modifying state.
    return json.loads(ALIAS_SERVICES.read_text(encoding="utf-8"))


def _first_uuid(section: str) -> str | None:
    # ES: Devuelve el primer UUID disponible de una sección.
    # EN: Return the first available UUID for a section.
    data = _read_alias_services()
    values = data.get(section, {})
    if isinstance(values, dict):
        for uuid in values:
            return uuid
    return None


def run(ctx) -> None:
    # ES: Ejecuta comprobaciones read-only de alias_services para viewer/admin.
    # EN: Execute read-only alias_services checks for viewer/admin.
    ctx.log("=== ALIAS_SERVICES NON-DESTRUCTIVE ===")

    status, payload = call(ctx, "status", "GET", "/api/v1/alias-services/status")
    require(ctx, status == 200, "status endpoint returns 200", f"status endpoint returned {status}")

    status, payload = call(ctx, "list services", "GET", "/api/v1/alias-services/services")
    require(ctx, status == 200 and isinstance(payload, dict) and payload.get("section") == "alias_service", "services list is readable", "services list failed")

    status, payload = call(ctx, "list service groups", "GET", "/api/v1/alias-services/service-groups")
    require(ctx, status == 200 and isinstance(payload, dict) and payload.get("section") == "alias_service_group", "service groups list is readable", "service groups list failed")

    service_uuid = _first_uuid("alias_service")
    if service_uuid:
        status, payload = call(ctx, "translate service", "POST", "/api/v1/alias-services/translate", {"UUID": service_uuid})
        require(ctx, status == 200 and payload.get("section") == "alias_service", "service translate works", "service translate failed")
        status, payload = call(ctx, "deep translate service", "POST", "/api/v1/alias-services/deep_translate", {"UUID": service_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content"), list), "service deep_translate works", "service deep_translate failed")
        status, payload = call(ctx, "deep translate sanitized service", "POST", "/api/v1/alias-services/deep_translate_sanitized", {"UUID": service_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content_sanitized"), list), "service deep_translate_sanitized works", "service deep_translate_sanitized failed")

    group_uuid = _first_uuid("alias_service_group")
    if group_uuid:
        status, payload = call(ctx, "translate service group", "POST", "/api/v1/alias-services/translate", {"UUID": group_uuid})
        require(ctx, status == 200 and payload.get("section") == "alias_service_group", "service group translate works", "service group translate failed")
        status, payload = call(ctx, "deep translate service group", "POST", "/api/v1/alias-services/deep_translate", {"UUID": group_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content"), list), "service group deep_translate works", "service group deep_translate failed")
        status, payload = call(ctx, "deep translate sanitized service group", "POST", "/api/v1/alias-services/deep_translate_sanitized", {"UUID": group_uuid})
        require(ctx, status == 200 and isinstance(payload.get("deep_content_sanitized"), list), "service group deep_translate_sanitized works", "service group deep_translate_sanitized failed")
