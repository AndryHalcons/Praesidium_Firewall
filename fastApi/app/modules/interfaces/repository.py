"""
Repositorio del módulo Interfaces.
Interfaces module repository.

ES: Único origen/destino permitido: /var/lib/praesidium/candidate/interfaces.json.
EN: Only allowed source/destination: /var/lib/praesidium/candidate/interfaces.json.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import config_path

FILENAME = "interfaces.json"
ALIAS_IP_FILENAME = "alias_ip.json"


def config_file_path():
    """Devuelve /var/lib/praesidium/candidate/interfaces.json."""
    return config_path("candidate", FILENAME)


def read_config() -> dict[str, Any]:
    """Lee candidate/interfaces.json."""
    data = read_json(config_file_path(), default={})
    return data if isinstance(data, dict) else {}


def write_config(data: dict[str, Any]) -> None:
    """Escribe candidate/interfaces.json de forma atómica."""
    write_json(config_file_path(), data)


def read_alias_ip() -> dict[str, Any]:
    """Lee candidate/alias_ip.json para validar alias_address y alias_addr_group."""
    data = read_json(config_path("candidate", ALIAS_IP_FILENAME), default={})
    return data if isinstance(data, dict) else {}


@contextmanager
def config_lock():
    """Bloquea candidate/interfaces.json durante escrituras concurrentes."""
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
