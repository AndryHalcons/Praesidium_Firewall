"""
Repositorio users.json para Praesidium FastAPI.
Praesidium FastAPI users.json repository.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import config_path


USERS_FILE = "users.json"


def users_path(area: str = "candidate"):
    """Ruta de users.json. / users.json path."""
    return config_path(area, USERS_FILE)


def read_users_config(area: str = "candidate") -> dict[str, Any]:
    """Lee users.json. / Read users.json."""
    data = read_json(users_path(area), default={})
    return data if isinstance(data, dict) else {}


def write_users_config(data: dict[str, Any], area: str = "candidate") -> None:
    """Escribe users.json. / Write users.json."""
    write_json(users_path(area), data)


def list_users(area: str = "candidate") -> list[dict[str, Any]]:
    """Lista usuarios. / List users."""
    data = read_users_config(area)
    users = data.get("table_users", [])
    return users if isinstance(users, list) else []


def save_users(users: list[dict[str, Any]], area: str = "candidate") -> dict[str, Any]:
    """Reemplaza table_users preservando el resto de users.json."""
    data = read_users_config(area)
    data["table_users"] = users
    write_users_config(data, area)
    return data


def find_user_by_username(username: str, area: str = "candidate") -> dict[str, Any] | None:
    """Busca usuario por nombre. / Find user by username."""
    for user in list_users(area):
        if str(user.get("user_name", "")) == username:
            return user
    return None


def find_user_by_uuid(user_uuid: str, area: str = "candidate") -> dict[str, Any] | None:
    """Busca usuario por UUID. / Find user by UUID."""
    for user in list_users(area):
        if str(user.get("UUID", "")) == user_uuid:
            return user
    return None


def replace_login_attempts(attempts: list[dict[str, Any]], area: str = "candidate") -> None:
    """Actualiza tabla de intentos de login. / Update login-attempt table."""
    data = read_users_config(area)
    data["table_login_attempts"] = attempts
    write_users_config(data, area)


@contextmanager
def users_config_lock(area: str = "candidate"):
    """Bloqueo exclusivo por área users.json. / Exclusive users.json area lock."""
    path = users_path(area)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
