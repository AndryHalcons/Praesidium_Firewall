"""Lógica de negocio del módulo System Logging."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

from modules.system_logging import repository

SIZE_VALUES = {"10M", "25M", "50M", "100M", "250M", "500M", "1G", "2G"}
RETENTION_VALUES = {"1day", "3day", "7day", "14day", "30day"}
ROTATION_VALUES = {"daily", "weekly"}

FIELD_RULES: dict[str, dict[str, tuple[str, object]]] = {
    "journald": {
        "uuid": ("static_uuid", None),
        "system_max_use": ("choice", SIZE_VALUES),
        "system_keep_free": ("choice", SIZE_VALUES),
        "runtime_max_use": ("choice", SIZE_VALUES),
        "max_retention_sec": ("choice", RETENTION_VALUES),
        "compress": ("bool", None),
    },
    "system_logs": {
        "uuid": ("static_uuid", None),
        "enabled": ("bool", None),
        "rotation": ("choice", ROTATION_VALUES),
        "rotate": ("int_range", (1, 30)),
        "maxsize": ("choice", SIZE_VALUES),
        "compress": ("bool", None),
        "delaycompress": ("bool", None),
    },
    "nftables_logs": {
        "uuid": ("static_uuid", None),
        "enabled": ("bool", None),
        "size": ("choice", SIZE_VALUES),
        "rotate": ("int_range", (1, 30)),
        "compress": ("bool", None),
        "delaycompress": ("bool", None),
    },
}


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """Lanza un error estable del módulo."""
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


def _field_error(section: str, field: str) -> str:
    """Construye el error estable de un campo."""
    return f"SYSTEM_LOGGING_{section}_{field}_INVALID".upper()


def _validate_field(section: str, field: str, value: Any, rule: tuple[str, object], *, malformed: bool) -> Any:
    """Valida un valor según la tabla declarativa."""
    kind, constraint = rule
    valid = False
    if kind == "choice":
        valid = isinstance(value, str) and value in constraint
    elif kind == "static_uuid":
        valid = isinstance(value, str) and bool(value.strip())
    elif kind == "bool":
        valid = type(value) is bool
    elif kind == "int_range":
        minimum, maximum = constraint
        valid = type(value) is int and minimum <= value <= maximum
    if not valid:
        if malformed:
            fail("SYSTEM_LOGGING_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        fail(_field_error(section, field))
    return value


def validate_section(section: str, data: Any, *, malformed: bool) -> dict[str, Any]:
    """Valida y normaliza una sección completa."""
    rules = FIELD_RULES[section]
    if not isinstance(data, dict) or any(field not in data for field in rules):
        if malformed:
            fail("SYSTEM_LOGGING_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        fail(f"SYSTEM_LOGGING_{section}_INVALID".upper())
    return {
        field: _validate_field(section, field, data[field], rule, malformed=malformed)
        for field, rule in rules.items()
    }


def normalize_candidate(data: Any) -> dict[str, dict[str, Any]]:
    """Valida el objeto candidate completo."""
    if not isinstance(data, dict):
        fail("SYSTEM_LOGGING_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    return {
        section: validate_section(section, data.get(section), malformed=True)
        for section in FIELD_RULES
    }


def read_candidate_config() -> dict[str, dict[str, Any]]:
    """Lee y valida candidate/system_logging.json."""
    return normalize_candidate(repository.read_config_raw())


def read_section(section: str) -> dict[str, Any]:
    """Lee una sección validada de candidate."""
    return read_candidate_config()[section]


def update_section(section: str, payload: Any) -> dict[str, Any]:
    """Actualiza parcialmente una sección sin aplicar cambios al sistema."""
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        fail("SYSTEM_LOGGING_EMPTY_PATCH")
    with repository.config_lock():
        raw = repository.read_config_raw()
        current = normalize_candidate(raw)
        merged = dict(current[section])
        merged.update(updates)
        normalized = validate_section(section, merged, malformed=False)
        data = dict(raw)
        stored_section = dict(data.get(section, {}))
        stored_section.update(normalized)
        data[section] = stored_section
        repository.write_config(data)
    return {"success": True, "section": section}
