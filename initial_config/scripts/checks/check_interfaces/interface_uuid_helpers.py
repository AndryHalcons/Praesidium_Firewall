"""
ES: Helpers de UUID estable para candidate/interfaces.json.
EN: Stable UUID helpers for candidate/interfaces.json.
"""
from __future__ import annotations

import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ES: Mapa estricto sección Netplan -> prefijo UUID Praesidium pedido para interfaces.
# EN: Strict Netplan section -> requested Praesidium UUID prefix for interfaces.
INTERFACE_UUID_PREFIXES = {
    "ethernets": "ethernet",
    "bridges": "bridge",
    "wifis": "wifi",
    "bonds": "bond",
    "vlans": "vlan",
}

_INTERNAL_UUID_RE = re.compile(
    r"^(?P<prefix>[A-Za-z0-9_]+)-(?P<object_id>[^-]+)-(?P<timestamp>\d{17})-(?P<random4>\d{4})$"
)
_OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _load_fastapi_generator():
    """ES: Reutiliza el generador FastAPI si está disponible. / EN: Reuse FastAPI generator when available."""
    candidates = [
        Path("/opt/praesidium/fastapi/app"),
        Path("/home/andres/Praesidium_Firewall/fastApi/app"),
    ]
    for candidate in candidates:
        if candidate.exists() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    try:
        from core.identifiers import generate_unique_internal_uuid  # type: ignore
        return generate_unique_internal_uuid
    except Exception:
        return None


def _timestamp_for_internal_uuid() -> str:
    """ES: Timestamp compatible con core.identifiers. / EN: core.identifiers-compatible timestamp."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d%H%M%S") + f"{now.microsecond // 1000:03d}"


def _fallback_generate_unique_internal_uuid(prefix: str, object_id: str, existing_uuids: set[str]) -> str:
    """ES: Fallback sólo para initial_config si FastAPI no está importable. / EN: Initial-config-only fallback."""
    clean_object_id = str(object_id).strip()
    if not clean_object_id or not _OBJECT_ID_RE.fullmatch(clean_object_id):
        raise ValueError("INVALID_UUID_OBJECT_ID")
    for _ in range(20):
        random_suffix = f"{random.randint(0, 9999):04d}"
        candidate = f"{prefix}-{clean_object_id}-{_timestamp_for_internal_uuid()}-{random_suffix}"
        if candidate not in existing_uuids:
            return candidate
    raise ValueError("UNABLE_TO_GENERATE_UNIQUE_UUID")


def _generate_uuid(prefix: str, object_id: str, existing_uuids: set[str]) -> str:
    """ES: Punto único de generación; FastAPI primero, fallback compatible después. / EN: Single generation point."""
    generator = _load_fastapi_generator()
    if generator is not None:
        try:
            return generator(prefix, object_id, existing_uuids)
        except Exception:
            # ES: Si el core FastAPI instalado aún no conoce estos prefijos, conserva compatibilidad.
            # EN: If installed FastAPI core does not know these prefixes yet, keep compatibility.
            pass
    return _fallback_generate_unique_internal_uuid(prefix, object_id, existing_uuids)


def valid_interface_uuid(value: Any, expected_prefix: str) -> bool:
    """ES: Valida formato y prefijo del UUID de interfaz. / EN: Validate interface UUID format and prefix."""
    if not isinstance(value, str):
        return False
    match = _INTERNAL_UUID_RE.fullmatch(value.strip())
    return bool(match and match.group("prefix") == expected_prefix)


def collect_interface_uuids(config: dict[str, Any]) -> set[str]:
    """ES: Recoge UUIDs existentes para evitar colisiones. / EN: Collect existing UUIDs to avoid collisions."""
    network = config.get("network") if isinstance(config, dict) else {}
    if not isinstance(network, dict):
        return set()
    found: set[str] = set()
    for section in INTERFACE_UUID_PREFIXES:
        entries = network.get(section, {})
        if not isinstance(entries, dict):
            continue
        for entry in entries.values():
            if isinstance(entry, dict):
                value = entry.get("uuid") or entry.get("UUID")
                if value:
                    found.add(str(value))
    return found


def order_interface_entry_uuid(entry: dict[str, Any], uuid: str) -> dict[str, Any]:
    """ES: Coloca uuid como primer campo sin alterar el resto. / EN: Put uuid first without changing other fields."""
    ordered: dict[str, Any] = {"uuid": uuid}
    for key, value in entry.items():
        if key in {"uuid", "UUID"}:
            continue
        ordered[key] = value
    return ordered


def ensure_interface_entry_uuid(config: dict[str, Any], section: str, name: str, entry: Any) -> dict[str, Any]:
    """ES: Preserva uuid válido o genera uno para una interfaz. / EN: Preserve valid uuid or generate one."""
    prefix = INTERFACE_UUID_PREFIXES[section]
    clean_entry = dict(entry) if isinstance(entry, dict) else {}
    current_uuid = str(clean_entry.get("uuid") or clean_entry.get("UUID") or "").strip()
    existing = collect_interface_uuids(config)
    if not valid_interface_uuid(current_uuid, prefix):
        current_uuid = _generate_uuid(prefix, name, existing)
    return order_interface_entry_uuid(clean_entry, current_uuid)


def ensure_interface_uuids(config: dict[str, Any]) -> dict[str, Any]:
    """ES: Asegura UUID estable en todas las familias de interfaces soportadas. / EN: Ensure stable UUIDs."""
    if not isinstance(config, dict):
        return config
    network = config.setdefault("network", {})
    if not isinstance(network, dict):
        return config
    for section in INTERFACE_UUID_PREFIXES:
        entries = network.setdefault(section, {})
        if not isinstance(entries, dict):
            network[section] = {}
            continue
        for name in list(entries.keys()):
            entries[name] = ensure_interface_entry_uuid(config, section, str(name), entries[name])
    return config


def new_interface_entry(config: dict[str, Any], section: str, name: str) -> dict[str, Any]:
    """ES: Crea entrada vacía con UUID estable para interfaz nueva. / EN: Create empty UUID-bearing entry."""
    return ensure_interface_entry_uuid(config, section, name, {})
