"""
Repositorio de Alias IP.
Alias IP repository.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import config_path

FILENAME = "alias_ip.json"


# Devuelve la ruta del JSON persistente de esta familia alias.
# Returns the persistent JSON path for this alias family.
def config_file_path(area: str = "candidate"):
    return config_path(area, FILENAME)


# Lee la configuración candidate/running de esta familia alias.
# Reads the candidate/running configuration for this alias family.
def read_config(area: str = "candidate") -> dict[str, Any]:
    data = read_json(config_file_path(area), default={})
    return data if isinstance(data, dict) else {}


# Escribe la configuración de esta familia alias de forma atómica.
# Writes this alias family configuration atomically.
def write_config(data: dict[str, Any], area: str = "candidate") -> None:
    write_json(config_file_path(area), data)


@contextmanager
# Bloquea el JSON de esta familia durante escrituras concurrentes.
# Locks this family JSON during concurrent writes.
def config_lock(area: str = "candidate"):
    path = config_file_path(area)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
