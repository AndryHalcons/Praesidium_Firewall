"""Repositorio del módulo WireGuard."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import SCRIPTS_DIR, config_path

FILENAME = "wireguard.json"
ALIAS_IP_FILENAME = "alias_ip.json"
ALIAS_SERVICES_FILENAME = "alias_services.json"


def config_file_path() -> Path:
    """Devuelve candidate/wireguard.json. / Return candidate/wireguard.json."""
    return config_path("candidate", FILENAME)


def scripts_dir() -> Path:
    """Devuelve el directorio runtime de helpers WireGuard."""
    return SCRIPTS_DIR / "wireguard"


def read_config_raw() -> Any:
    """Lee el JSON candidate sin normalizar para detectar shape rota."""
    return read_json(config_file_path(), default={"site_to_site": {}, "remote_access": {}, "remote_clients": {}})


def write_config(data: dict[str, Any]) -> None:
    """Escribe candidate/wireguard.json de forma atómica."""
    write_json(config_file_path(), data)


def read_alias_ip() -> dict[str, Any]:
    """Lee alias_ip candidate para validación delegada. / Read alias_ip candidate for delegated validation."""
    data = read_json(config_path("candidate", ALIAS_IP_FILENAME), default={})
    return data if isinstance(data, dict) else {}


def read_alias_services() -> dict[str, Any]:
    """Lee alias_services candidate para validación delegada. / Read alias_services candidate for delegated validation."""
    data = read_json(config_path("candidate", ALIAS_SERVICES_FILENAME), default={})
    return data if isinstance(data, dict) else {}


@contextmanager
def config_lock():
    """Bloquea candidate/wireguard.json durante escrituras concurrentes."""
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
