"""Gestión admin de login_attempts reales en running/users.json."""

from __future__ import annotations

from typing import Any

from modules.users.repository import read_users_config, users_config_lock, write_users_config


def _rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("table_login_attempts", [])
    return rows if isinstance(rows, list) else []


def list_login_attempts() -> list[dict[str, str]]:
    data = read_users_config("running")
    return [
        {
            "client_ip": str(row.get("client_ip", "")),
            "usernames": str(row.get("usernames", "")),
            "failed_count": str(row.get("failed_count", "0")),
            "first_failed_at": str(row.get("first_failed_at", "")),
            "locked_until": str(row.get("locked_until", "")),
        }
        for row in _rows(data)
    ]


def delete_login_attempt(client_ip: str) -> dict[str, str]:
    with users_config_lock("running"):
        data = read_users_config("running")
        data["table_login_attempts"] = [row for row in _rows(data) if str(row.get("client_ip", "")) != client_ip]
        write_users_config(data, "running")
    return {"status": "ok", "deleted_client_ip": client_ip}
