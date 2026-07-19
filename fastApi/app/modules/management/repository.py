"""Repositorio del módulo Management."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import config_path

FILENAME = "management.json"


def config_file_path() -> Path:
    """Devuelve candidate/management.json."""
    return config_path("candidate", FILENAME)


def read_config_raw() -> Any:
    """Lee candidate/management.json sin normalizar."""
    return read_json(config_file_path(), default={})


def write_config(data: dict[str, Any]) -> None:
    """Escribe candidate/management.json de forma atómica."""
    write_json(config_file_path(), data)


@contextmanager
def config_lock():
    """Bloquea candidate/management.json durante escrituras concurrentes."""
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
