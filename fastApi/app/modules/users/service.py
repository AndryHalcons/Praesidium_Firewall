"""
Lógica del módulo Users.
Users module logic.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid
from core.security.password import hash_password, verify_password
from modules.users.repository import find_user_by_username, list_users, read_users_config, users_config_lock, write_users_config

_TRUE_FALSE = {"true", "false"}
_COMMON_PASSWORDS = {
    "password", "password1", "password123", "admin", "admin123", "praesidium",
    "qwerty", "qwerty123", "123456", "12345678", "123456789", "111111",
    "letmein", "welcome", "changeme", "root", "toor",
}


def _now() -> str:
    """Fecha interna ISO UTC. / Internal UTC ISO date."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_time(value: str) -> datetime | None:
    """Parsea fecha ISO. / Parse ISO date."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _as_bool_text(value: Any, default: str = "false") -> str:
    """Normaliza booleano textual. / Normalize textual boolean."""
    if value is None:
        value = default
    clean = str(value).strip().lower()
    if clean not in _TRUE_FALSE:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_BOOLEAN_FIELD")
    return clean


def _policy(data: dict[str, Any]) -> dict[str, Any]:
    """Devuelve política de contraseña con defaults legacy."""
    defaults = {
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
    }
    table = data.get("table_password_policy", [])
    if isinstance(table, list) and table and isinstance(table[0], dict):
        defaults.update(table[0])
    return defaults


def _policy_bool(policy: dict[str, Any], key: str) -> bool:
    return str(policy.get(key, "false")).strip().lower() == "true"


def _policy_int(policy: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(policy.get(key, default))
    except (TypeError, ValueError):
        return default


def _find_user_index_by_uuid(users: list[dict[str, Any]], user_uuid: str) -> int | None:
    for index, user in enumerate(users):
        if str(user.get("UUID", "")) == user_uuid:
            return index
    return None


def _find_user_index_by_name(users: list[dict[str, Any]], username: str) -> int | None:
    for index, user in enumerate(users):
        if str(user.get("user_name", "")) == username:
            return index
    return None


def _ensure_unique_username(users: list[dict[str, Any]], username: str, ignore_uuid: str = "") -> None:
    """Evita usuarios duplicados. / Avoid duplicate users."""
    for user in users:
        if ignore_uuid and str(user.get("UUID", "")) == ignore_uuid:
            continue
        if str(user.get("user_name", "")) == username:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="USER_ALREADY_EXISTS")


def _ensure_admin_remains(users: list[dict[str, Any]]) -> None:
    """Impide dejar table_users sin ningún admin. / Prevent table_users with no admin."""
    if not any(str(user.get("user_role", "")) == "admin" for user in users):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="LAST_ADMIN_REQUIRED")


def _next_id(users: list[dict[str, Any]]) -> str:
    """Devuelve el menor id positivo libre empezando en 1."""
    used_ids: set[int] = set()
    for user in users:
        try:
            value = int(str(user.get("id", "")))
        except ValueError:
            continue
        if value > 0:
            used_ids.add(value)
    candidate = 1
    while candidate in used_ids:
        candidate += 1
    return str(candidate)


def validate_password_policy(password: str, username: str, data: dict[str, Any]) -> None:
    """Aplica complejidad y listas comunes del legacy."""
    policy = _policy(data)
    min_len = max(0, _policy_int(policy, "password_min_length", 12))
    if len(password) < min_len:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_TOO_SHORT")
    if _policy_bool(policy, "password_require_uppercase") and not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_REQUIRES_UPPERCASE")
    if _policy_bool(policy, "password_require_lowercase") and not re.search(r"[a-z]", password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_REQUIRES_LOWERCASE")
    if _policy_bool(policy, "password_require_number") and not re.search(r"[0-9]", password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_REQUIRES_NUMBER")
    if _policy_bool(policy, "password_require_symbol") and not re.search(r"[^A-Za-z0-9]", password):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_REQUIRES_SYMBOL")
    if _policy_bool(policy, "password_disallow_username") and username and username.lower() in password.lower():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_CONTAINS_USERNAME")
    if _policy_bool(policy, "password_disallow_common_passwords") and password.lower() in _COMMON_PASSWORDS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_TOO_COMMON")


def _validate_password_min_age(existing: dict[str, Any] | None, data: dict[str, Any], bypass: bool = False) -> None:
    """Aplica password_min_age_days salvo bypass obligatorio."""
    if bypass:
        return
    policy = _policy(data)
    min_age_days = _policy_int(policy, "password_min_age_days", 0)
    if min_age_days <= 0 or not existing:
        return
    changed_at = _parse_time(str(existing.get("password_changed_at", "")))
    if changed_at is None:
        return
    if (datetime.now(timezone.utc) - changed_at).total_seconds() < min_age_days * 86400:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_CHANGED_TOO_SOON")


def _recent_password_hashes(data: dict[str, Any], user: dict[str, Any] | None) -> list[str]:
    """Devuelve hashes recientes: hash actual + historial ordenado reciente."""
    if not user:
        return []
    policy = _policy(data)
    count = _policy_int(policy, "password_history_count", 0)
    if count <= 0:
        return []
    hashes: list[str] = []
    current = str(user.get("user_pass", ""))
    if current:
        hashes.append(current)
    user_id = str(user.get("id", ""))
    rows = data.get("table_password_history", [])
    if isinstance(rows, list):
        history = [row for row in rows if str(row.get("user_id", "")) == user_id]
        history.sort(key=lambda row: str(row.get("changed_at", "")), reverse=True)
        hashes.extend(str(row.get("password_hash", "")) for row in history[:count] if row.get("password_hash"))
    return hashes


def _check_password_history(password: str, user: dict[str, Any] | None, data: dict[str, Any]) -> None:
    """Impide reutilizar contraseña actual o recientes."""
    for stored_hash in _recent_password_hashes(data, user):
        if verify_password(password, stored_hash):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_REUSED")


def _append_password_history(data: dict[str, Any], user_id: str, password_hash: str, changed_at: str) -> None:
    """Añade historial y recorta por usuario igual que legacy."""
    rows = data.get("table_password_history", [])
    if not isinstance(rows, list):
        rows = []
    rows.append({"user_id": str(user_id), "password_hash": password_hash, "changed_at": changed_at})
    count = _policy_int(_policy(data), "password_history_count", 0)
    if count > 0:
        by_user: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            by_user.setdefault(str(row.get("user_id", "")), []).append(row)
        trimmed: list[dict[str, Any]] = []
        for entries in by_user.values():
            entries.sort(key=lambda row: str(row.get("changed_at", "")), reverse=True)
            trimmed.extend(entries[:count])
        rows = trimmed
    data["table_password_history"] = rows


def public_user(user: dict[str, Any]) -> dict[str, str]:
    """Elimina campos sensibles. / Remove sensitive fields."""
    return {
        "id": str(user.get("id", "")),
        "UUID": str(user.get("UUID", "")),
        "user_name": str(user.get("user_name", "")),
        "user_role": str(user.get("user_role", "")),
        "user_language": str(user.get("user_language", "")),
        "password_changed_at": str(user.get("password_changed_at", "")),
        "force_password_change": str(user.get("force_password_change", "false")),
    }


def list_public_users() -> list[dict[str, str]]:
    """Lista usuarios candidate sin hashes. / List candidate users without hashes."""
    return [public_user(user) for user in list_users("candidate")]


def create_user(payload: Any) -> dict[str, str]:
    """Crea usuario en candidate aplicando política legacy."""
    with users_config_lock("candidate"):
        data = read_users_config("candidate")
        users = list(data.get("table_users", []) or [])
        _ensure_unique_username(users, payload.user_name)
        validate_password_policy(payload.user_pass, payload.user_name, data)
        new_id = _next_id(users)
        existing_uuids = {str(u.get("UUID", "")) for u in users if u.get("UUID")}
        changed_at = _now()
        password_hash = hash_password(payload.user_pass)
        force_default = "true" if _policy_bool(_policy(data), "force_password_change_for_new_users") else "false"
        user = {
            "id": new_id,
            "UUID": generate_unique_internal_uuid("users", new_id, existing_uuids),
            "user_name": payload.user_name,
            "user_pass": password_hash,
            "user_role": payload.user_role,
            "user_language": payload.user_language,
            "password_changed_at": changed_at,
            "force_password_change": _as_bool_text(payload.force_password_change, force_default),
        }
        users.append(user)
        data["table_users"] = users
        _append_password_history(data, new_id, password_hash, changed_at)
        write_users_config(data, "candidate")
        return public_user(user)

def update_user(user_uuid: str, payload: Any) -> dict[str, str]:
    """Edita usuario preservando UUID/password_changed_at/user_pass."""
    with users_config_lock("candidate"):
        data = read_users_config("candidate")
        users = list(data.get("table_users", []) or [])
        idx = _find_user_index_by_uuid(users, user_uuid)
        if idx is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="USER_NOT_FOUND")
        user = users[idx]
        if payload.user_name is not None:
            _ensure_unique_username(users, payload.user_name, user_uuid)
            user["user_name"] = payload.user_name
        if payload.user_role is not None:
            user["user_role"] = payload.user_role
        if payload.user_language is not None:
            user["user_language"] = payload.user_language
        if payload.force_password_change is not None:
            user["force_password_change"] = _as_bool_text(payload.force_password_change)
        users[idx] = user
        _ensure_admin_remains(users)
        data["table_users"] = users
        write_users_config(data, "candidate")
        return public_user(user)

def delete_user(user_uuid: str) -> dict[str, str]:
    """Borra usuario completo por UUID. / Delete complete user by UUID."""
    with users_config_lock("candidate"):
        data = read_users_config("candidate")
        users = list(data.get("table_users", []) or [])
        idx = _find_user_index_by_uuid(users, user_uuid)
        if idx is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="USER_NOT_FOUND")
        target = users.pop(idx)
        _ensure_admin_remains(users)
        data["table_users"] = users
        user_id = str(target.get("id", ""))
        rows = data.get("table_password_history", [])
        if isinstance(rows, list):
            data["table_password_history"] = [row for row in rows if str(row.get("user_id", "")) != user_id]
        write_users_config(data, "candidate")
        return {"status": "ok", "deleted_uuid": user_uuid}

def change_user_password(user_uuid: str, payload: Any, admin_username: str) -> dict[str, str]:
    """Cambio admin en candidate validando contraseña actual del admin."""
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_CONFIRM_MISMATCH")

    admin = find_user_by_username(admin_username, "running")
    if admin is None or not verify_password(payload.current_password, str(admin.get("user_pass", ""))):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CURRENT_PASSWORD_INCORRECT")

    with users_config_lock("candidate"):
        data = read_users_config("candidate")
        users = list(data.get("table_users", []) or [])
        idx = _find_user_index_by_uuid(users, user_uuid)
        if idx is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="USER_NOT_FOUND")
        user = users[idx]
        validate_password_policy(payload.new_password, str(user.get("user_name", "")), data)
        _check_password_history(payload.new_password, user, data)
        _validate_password_min_age(user, data)
        changed_at = _now()
        password_hash = hash_password(payload.new_password)
        user["user_pass"] = password_hash
        user["password_changed_at"] = changed_at
        user["force_password_change"] = _as_bool_text(payload.force_password_change, "false") if payload.force_password_change is not None else "false"
        users[idx] = user
        data["table_users"] = users
        _append_password_history(data, str(user.get("id", "")), password_hash, changed_at)
        write_users_config(data, "candidate")
        return public_user(user)

def _change_password_in_area(area: str, username: str, current_password: str, new_password: str, bypass_min_age: bool) -> tuple[dict[str, Any], dict[str, str]] | None:
    """Prepara cambio self-service en un área; no escribe disco."""
    data = read_users_config(area)
    users = list(data.get("table_users", []) or [])
    idx = _find_user_index_by_name(users, username)
    if idx is None:
        return None
    user = users[idx]
    if not verify_password(current_password, str(user.get("user_pass", ""))):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CURRENT_PASSWORD_INCORRECT")
    if new_password == current_password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_REUSED")
    validate_password_policy(new_password, username, data)
    _check_password_history(new_password, user, data)
    _validate_password_min_age(user, data, bypass=bypass_min_age)
    changed_at = _now()
    password_hash = hash_password(new_password)
    user["user_pass"] = password_hash
    user["password_changed_at"] = changed_at
    user["force_password_change"] = "false"
    users[idx] = user
    data["table_users"] = users
    _append_password_history(data, str(user.get("id", "")), password_hash, changed_at)
    return data, public_user(user)


def change_own_password(username: str, current_password: str, new_password: str, confirm_password: str, bypass_min_age: bool = False) -> dict[str, str]:
    """Cambio de contraseña del usuario autenticado, running + candidate si existe."""
    if not current_password or not new_password or not confirm_password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_FIELDS_REQUIRED")
    if new_password != confirm_password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="PASSWORD_CONFIRM_MISMATCH")

    # ES: Se preparan running y candidate antes de escribir para evitar cambios parciales.
    # EN: Prepare running and candidate before writing to avoid partial changes.
    with users_config_lock("running"):
        with users_config_lock("candidate"):
            running_result = _change_password_in_area("running", username, current_password, new_password, bypass_min_age)
            if running_result is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="USER_NOT_FOUND")
            candidate_result = _change_password_in_area("candidate", username, current_password, new_password, bypass_min_age)
            running_data, public = running_result
            write_users_config(running_data, "running")
            if candidate_result is not None:
                candidate_data, _ = candidate_result
                write_users_config(candidate_data, "candidate")
            return public

def module_name() -> str:
    """Devuelve el nombre interno del módulo. / Return internal module name."""
    return "users"
