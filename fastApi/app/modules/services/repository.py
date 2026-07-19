"""Repositorio del módulo Services."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import config_path

FILENAME = "services.json"


def config_file_path() -> Path:
    """Devuelve candidate/services.json."""
    return config_path("candidate", FILENAME)


def read_config_raw() -> Any:
    """Lee services.json sin normalizar para detectar shape rota."""
    return read_json(config_file_path(), default={"services": {}})


def write_config(data: dict[str, Any]) -> None:
    """Escribe candidate/services.json de forma atómica."""
    write_json(config_file_path(), data)


@contextmanager
def config_lock():
    """Bloquea candidate/services.json durante escrituras concurrentes."""
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
