"""Lógica de negocio FastAPI para Management."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid
from modules.management import repository

LISTENER = "table_management_listener"
ALLOWED_SOURCES = "table_management_allowed_sources"
TLS = "table_management_tls"
TABLES = (LISTENER, ALLOWED_SOURCES, TLS)
UUID_PREFIX = {
    LISTENER: "listenerapache",
    ALLOWED_SOURCES: "managementnetworks",
    TLS: "certtls",
}
SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
CERT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """Lanza error estable status/error_code."""
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


def clean(value: Any) -> str:
    """Normaliza texto simple."""
    return str(value or "").strip()


def public_row(row: dict[str, Any]) -> dict[str, Any]:
    """Devuelve fila visible sin UUID interno."""
    out = dict(row)
    out.pop("UUID", None)
    return out


def ensure_config(data: Any) -> dict[str, Any]:
    """Valida shape raíz de management.json."""
    if not isinstance(data, dict):
        fail("MANAGEMENT_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    out = dict(data)
    for table in TABLES:
        value = out.get(table, [])
        if not isinstance(value, list):
            fail("MANAGEMENT_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        for row in value:
            if not isinstance(row, dict):
                fail("MANAGEMENT_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        out[table] = list(value)
    return out


def read_config() -> dict[str, Any]:
    """Lee candidate/management.json normalizado."""
    return ensure_config(repository.read_config_raw())


def public_config() -> dict[str, Any]:
    """Devuelve config visible sin UUIDs internos."""
    data = read_config()
    return {table: [public_row(row) for row in data.get(table, [])] for table in TABLES}


def existing_uuids(data: dict[str, Any]) -> set[str]:
    """Recoge UUIDs existentes."""
    return {str(row.get("UUID")) for table in TABLES for row in data.get(table, []) if row.get("UUID")}


def next_id(rows: list[dict[str, Any]]) -> str:
    """Calcula siguiente id numérico."""
    max_id = 0
    for row in rows:
        try:
            max_id = max(max_id, int(str(row.get("id", "0"))))
        except ValueError:
            continue
    return str(max_id + 1)


def set_internal_uuid(row: dict[str, Any], uuid: str) -> dict[str, Any]:
    """Inserta UUID junto a id para legibilidad compatible."""
    ordered: dict[str, Any] = {}
    inserted = False
    for key, value in row.items():
        if key == "UUID":
            continue
        ordered[key] = value
        if key == "id":
            ordered["UUID"] = uuid
            inserted = True
    if not inserted:
        ordered["UUID"] = uuid
    return ordered


def validate_id(value: Any, *, required: bool = False) -> str:
    """Valida id numérico histórico."""
    text = clean(value)
    if not text:
        if required:
            fail("MANAGEMENT_ID_REQUIRED")
        return ""
    if not re.fullmatch(r"[1-9][0-9]{0,5}", text):
        fail("MANAGEMENT_ID_INVALID")
    return text


def validate_listener(payload: dict[str, Any]) -> dict[str, Any]:
    """Valida fila listener como legacy."""
    out: dict[str, Any] = {}
    row_id = validate_id(payload.get("id")) or "1"
    ip = clean(payload.get("listen_ip"))
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        fail("MANAGEMENT_LISTEN_IP_INVALID")
    try:
        port = int(clean(payload.get("listen_port")))
    except ValueError:
        fail("MANAGEMENT_LISTEN_PORT_INVALID")
    if not 1 <= port <= 65535:
        fail("MANAGEMENT_LISTEN_PORT_INVALID")
    server_name = clean(payload.get("server_name") or "praesidium.local")
    if not SERVER_NAME_RE.fullmatch(server_name) or server_name.startswith(".") or server_name.endswith(".") or ".." in server_name:
        fail("MANAGEMENT_SERVER_NAME_INVALID")
    out["id"] = row_id
    out["listen_ip"] = ip
    out["listen_port"] = str(port)
    out["server_name"] = server_name
    return out


def validate_cidr(value: Any) -> str:
    """Valida CIDR IPv4/IPv6 real."""
    cidr = clean(value)
    if "/" not in cidr:
        fail("MANAGEMENT_SOURCE_CIDR_INVALID")
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        fail("MANAGEMENT_SOURCE_CIDR_INVALID")
    return cidr


def validate_description(value: Any) -> str:
    """Valida descripción visual."""
    text = CONTROL_CHARS_RE.sub("", clean(value))
    return text[:160]


def validate_allowed_source(payload: dict[str, Any], *, partial: bool = False) -> dict[str, Any]:
    """Valida fila allowed_sources."""
    out: dict[str, Any] = {}
    row_id = validate_id(payload.get("id"))
    if row_id:
        out["id"] = row_id
    if not partial or payload.get("source_cidr") is not None:
        out["source_cidr"] = validate_cidr(payload.get("source_cidr"))
    if not partial or payload.get("description") is not None:
        out["description"] = validate_description(payload.get("description", ""))
    return out


def validate_tls_file(value: Any, field: str) -> str:
    """Valida nombre de archivo TLS local seguro."""
    name = os.path.basename(clean(value))
    if not CERT_NAME_RE.fullmatch(name):
        fail(f"MANAGEMENT_{field.upper()}_INVALID")
    return name


def validate_tls(payload: dict[str, Any]) -> dict[str, Any]:
    """Valida fila TLS como legacy."""
    row_id = validate_id(payload.get("id")) or "1"
    return {
        "id": row_id,
        "certificate_file": validate_tls_file(payload.get("certificate_file"), "certificate_file"),
        "certificate_key": validate_tls_file(payload.get("certificate_key"), "certificate_key"),
        "certificate_chain": validate_tls_file(payload.get("certificate_chain"), "certificate_chain"),
    }


def preserve_or_generate_uuid(data: dict[str, Any], table: str, row_id: str, existing: dict[str, Any] | None = None) -> str:
    """Preserva UUID existente o genera uno nuevo."""
    if existing and clean(existing.get("UUID")):
        return clean(existing.get("UUID"))
    return generate_unique_internal_uuid(UUID_PREFIX[table], row_id, existing_uuids(data))


def get_listener() -> dict[str, Any]:
    """Devuelve listener visible."""
    rows = read_config().get(LISTENER, [])
    return public_row(rows[0]) if rows else {}


def update_listener(payload: dict[str, Any]) -> dict[str, Any]:
    """Actualiza listener singleton en candidate."""
    normalized = validate_listener(payload)
    with repository.config_lock():
        data = read_config()
        existing = data.get(LISTENER, [None])[0] if data.get(LISTENER) else None
        uuid = preserve_or_generate_uuid(data, LISTENER, normalized["id"], existing if isinstance(existing, dict) else None)
        data[LISTENER] = [set_internal_uuid(normalized, uuid)]
        repository.write_config(data)
    return {"success": True, "section": "listener", "id": normalized["id"]}


def get_tls() -> dict[str, Any]:
    """Devuelve TLS visible."""
    rows = read_config().get(TLS, [])
    return public_row(rows[0]) if rows else {}


def update_tls(payload: dict[str, Any]) -> dict[str, Any]:
    """Actualiza TLS singleton en candidate."""
    normalized = validate_tls(payload)
    with repository.config_lock():
        data = read_config()
        existing = data.get(TLS, [None])[0] if data.get(TLS) else None
        uuid = preserve_or_generate_uuid(data, TLS, normalized["id"], existing if isinstance(existing, dict) else None)
        data[TLS] = [set_internal_uuid(normalized, uuid)]
        repository.write_config(data)
    return {"success": True, "section": "tls", "id": normalized["id"]}


def list_allowed_sources() -> list[dict[str, Any]]:
    """Lista fuentes permitidas visibles."""
    return [public_row(row) for row in read_config().get(ALLOWED_SOURCES, [])]


def find_allowed_source(data: dict[str, Any], source_id: str) -> tuple[int, dict[str, Any]]:
    """Busca allowed_source por id."""
    sid = validate_id(source_id, required=True)
    for idx, row in enumerate(data.get(ALLOWED_SOURCES, [])):
        if clean(row.get("id")) == sid:
            return idx, row
    fail("MANAGEMENT_ALLOWED_SOURCE_NOT_FOUND", status.HTTP_404_NOT_FOUND)


def get_allowed_source(source_id: str) -> dict[str, Any]:
    """Devuelve una fuente permitida."""
    data = read_config()
    _, row = find_allowed_source(data, source_id)
    return public_row(row)


def ensure_cidr_unique(rows: list[dict[str, Any]], cidr: str, *, ignore_id: str = "") -> None:
    """Evita duplicados de source_cidr."""
    for row in rows:
        if ignore_id and clean(row.get("id")) == ignore_id:
            continue
        if clean(row.get("source_cidr")) == cidr:
            fail("MANAGEMENT_SOURCE_CIDR_DUPLICATE", status.HTTP_409_CONFLICT)


def create_allowed_source(payload: dict[str, Any]) -> dict[str, Any]:
    """Crea una fuente permitida."""
    normalized = validate_allowed_source(payload)
    with repository.config_lock():
        data = read_config()
        rows = list(data.get(ALLOWED_SOURCES, []))
        normalized["id"] = next_id(rows)
        ensure_cidr_unique(rows, normalized["source_cidr"])
        uuid = generate_unique_internal_uuid(UUID_PREFIX[ALLOWED_SOURCES], normalized["id"], existing_uuids(data))
        rows.append(set_internal_uuid(normalized, uuid))
        data[ALLOWED_SOURCES] = rows
        repository.write_config(data)
    return {"success": True, "section": "allowed_sources", "id": normalized["id"]}


def update_allowed_source(source_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Actualiza una fuente permitida."""
    sid = validate_id(source_id, required=True)
    patch = validate_allowed_source(payload, partial=True)
    if not patch:
        fail("MANAGEMENT_EMPTY_PATCH")
    with repository.config_lock():
        data = read_config()
        idx, existing = find_allowed_source(data, sid)
        merged = dict(existing)
        merged.update(patch)
        merged["id"] = sid
        normalized = validate_allowed_source(merged)
        normalized["id"] = sid
        ensure_cidr_unique(data[ALLOWED_SOURCES], normalized["source_cidr"], ignore_id=sid)
        uuid = preserve_or_generate_uuid(data, ALLOWED_SOURCES, sid, existing)
        data[ALLOWED_SOURCES][idx] = set_internal_uuid(normalized, uuid)
        repository.write_config(data)
    return {"success": True, "section": "allowed_sources", "id": sid}


def delete_allowed_source(source_id: str) -> dict[str, Any]:
    """Borra una fuente permitida por id."""
    sid = validate_id(source_id, required=True)
    with repository.config_lock():
        data = read_config()
        rows = list(data.get(ALLOWED_SOURCES, []))
        new_rows = [row for row in rows if clean(row.get("id")) != sid]
        if len(new_rows) == len(rows):
            fail("MANAGEMENT_ALLOWED_SOURCE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        data[ALLOWED_SOURCES] = new_rows
        repository.write_config(data)
    return {"success": True, "section": "allowed_sources", "id": sid}
