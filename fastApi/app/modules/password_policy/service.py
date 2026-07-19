"""
Lógica del módulo Password Policy.
Password Policy module logic.

Aunque escribe en users.json, es un módulo lógico separado de users/auth.
Although it writes users.json, it is a logical module separate from users/auth.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid
from modules.users.repository import read_users_config, users_config_lock, write_users_config


BOOL_FIELDS = {
    "password_require_uppercase",
    "password_require_lowercase",
    "password_require_number",
    "password_require_symbol",
    "force_password_change_on_next_login",
    "force_password_change_for_new_users",
    "password_disallow_username",
    "password_disallow_common_passwords",
}

INT_RANGES = {
    "password_min_length": (8, 128),
    "password_expiration_days": (0, 3650),
    "password_history_count": (0, 50),
    "password_min_age_days": (0, 365),
    "login_max_failed_attempts": (1, 100),
    "login_lockout_minutes": (0, 1440),
    "login_failed_window_minutes": (1, 1440),
}

DEFAULT_POLICY = {
    "id": "1",
    "UUID": "",
    "password_min_length": "12",
    "password_require_uppercase": "true",
    "password_require_lowercase": "true",
    "password_require_number": "true",
    "password_require_symbol": "true",
    "password_expiration_days": "90",
    "password_history_count": "5",
    "password_min_age_days": "1",
    "login_max_failed_attempts": "5",
    "login_lockout_minutes": "30",
    "login_failed_window_minutes": "15",
    "force_password_change_on_next_login": "false",
    "force_password_change_for_new_users": "true",
    "password_disallow_username": "true",
    "password_disallow_common_passwords": "true",
    "force_password_change_since": "",
}


def _now() -> str:
    """Fecha UTC ISO. / UTC ISO date."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _ensure_policy(data: dict[str, Any]) -> dict[str, str]:
    """Devuelve la política singleton normalizada sin escribir disco."""
    table = data.get("table_password_policy", [])
    current = table[0] if isinstance(table, list) and table and isinstance(table[0], dict) else {}
    policy = dict(DEFAULT_POLICY)
    policy.update({str(k): str(v) for k, v in current.items()})
    policy["id"] = "1"
    if not policy.get("UUID"):
        existing = {str(row.get("UUID", "")) for row in data.get("table_users", []) if isinstance(row, dict)}
        policy["UUID"] = generate_unique_internal_uuid("passpolicy", "1", existing)
    return policy


def _normalize_bool(value: Any) -> str:
    clean = str(value).strip().lower()
    if clean not in {"true", "false"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_BOOLEAN_FIELD")
    return clean


def _normalize_int(field: str, value: Any) -> str:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"INVALID_INTEGER_FIELD:{field}")
    min_value, max_value = INT_RANGES[field]
    if number < min_value or number > max_value:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"FIELD_OUT_OF_RANGE:{field}")
    return str(number)


def _save_policy(data: dict[str, Any], policy: dict[str, str]) -> None:
    """Guarda singleton table_password_policy preservando el resto de users.json."""
    data["table_password_policy"] = [policy]
    write_users_config(data, "candidate")


def get_policy() -> dict[str, str]:
    """Lee política desde candidate/users.json."""
    data = read_users_config("candidate")
    return _ensure_policy(data)


def update_policy(payload: Any) -> dict[str, str]:
    """Actualiza table_password_policy en candidate/users.json."""
    with users_config_lock("candidate"):
        data = read_users_config("candidate")
        policy = _ensure_policy(data)
        updates = payload.model_dump(exclude_unset=True)
        previous_force = policy.get("force_password_change_on_next_login", "false")

        for field, value in updates.items():
            if field in BOOL_FIELDS:
                policy[field] = _normalize_bool(value)
            elif field in INT_RANGES:
                policy[field] = _normalize_int(field, value)
            else:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"UNKNOWN_POLICY_FIELD:{field}")

        # ES: La marca temporal del force global es interna, no editable por payload.
        # EN: The global-force timestamp is internal, not editable by payload.
        if previous_force != "true" and policy.get("force_password_change_on_next_login") == "true":
            policy["force_password_change_since"] = _now()
        if policy.get("force_password_change_on_next_login") == "false":
            policy["force_password_change_since"] = ""

        _save_policy(data, policy)
        return policy

def enable_force_change() -> dict[str, str]:
    """Activa cambio obligatorio global y genera force_password_change_since."""
    with users_config_lock("candidate"):
        data = read_users_config("candidate")
        policy = _ensure_policy(data)
        policy["force_password_change_on_next_login"] = "true"
        policy["force_password_change_since"] = _now()
        _save_policy(data, policy)
        return policy

def clear_force_change() -> dict[str, str]:
    """Desactiva cambio obligatorio global."""
    with users_config_lock("candidate"):
        data = read_users_config("candidate")
        policy = _ensure_policy(data)
        policy["force_password_change_on_next_login"] = "false"
        policy["force_password_change_since"] = ""
        _save_policy(data, policy)
        return policy
