"""
Repositorio del módulo Dnsmasq.
Dnsmasq module repository.

ES: Único origen/destino permitido: /var/lib/praesidium/candidate/dhcp.json.
EN: Only allowed source/destination: /var/lib/praesidium/candidate/dhcp.json.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import config_path, STATE_DIR

FILENAME = "dhcp.json"
ALIAS_IP_FILENAME = "alias_ip.json"
INTERFACES_FILENAME = "interfaces.json"


def config_file_path() -> Path:
    """Devuelve candidate/dhcp.json. / Return candidate/dhcp.json."""
    return config_path("candidate", FILENAME)


def read_config_raw() -> Any:
    """Lee dhcp.json sin normalizar para detectar shape rota."""
    return read_json(config_file_path(), default={"dhcp": [], "dhcp_reservation": []})


def write_config(data: dict[str, Any]) -> None:
    """Escribe dhcp.json de forma atómica. / Atomically write dhcp.json."""
    write_json(config_file_path(), data)


def read_alias_ip() -> dict[str, Any]:
    """Lee candidate/alias_ip.json para validar alias_address."""
    data = read_json(config_path("candidate", ALIAS_IP_FILENAME), default={})
    return data if isinstance(data, dict) else {}


def read_interfaces() -> dict[str, Any]:
    """Lee candidate/interfaces.json, única fuente autorizadora para dnsmasq."""
    data = read_json(config_path("candidate", INTERFACES_FILENAME), default={})
    return data if isinstance(data, dict) else {}


def read_state_interfaces() -> dict[str, Any]:
    """Lee state/interfaces sólo para diagnóstico/listado informativo."""
    path = STATE_DIR / "interfaces" / "all_interfaces_list.json"
    data = read_json(path, default={})
    return data if isinstance(data, dict) else {}


@contextmanager
def config_lock():
    """Bloquea candidate/dhcp.json durante escrituras concurrentes."""
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
