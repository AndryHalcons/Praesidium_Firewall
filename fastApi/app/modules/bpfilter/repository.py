"""
Repositorio del módulo BPFilter.

ES: Único origen/destino permitido: /var/lib/praesidium/candidate/rules_bpfilter_human_viewer.json.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import config_path, STATE_DIR

FILENAME = "rules_bpfilter_human_viewer.json"
ALIAS_IP_FILENAME = "alias_ip.json"
ALIAS_SERVICES_FILENAME = "alias_services.json"
PHYSICAL_INTERFACES = STATE_DIR / "interfaces" / "physical_interfaces_list.json"


def config_file_path():
    return config_path("candidate", FILENAME)


def read_config() -> dict[str, Any]:
    data = read_json(config_file_path(), default={})
    return data if isinstance(data, dict) else {}


def write_config(data: dict[str, Any]) -> None:
    write_json(config_file_path(), data)


def read_alias_ip() -> dict[str, Any]:
    data = read_json(config_path("candidate", ALIAS_IP_FILENAME), default={})
    return data if isinstance(data, dict) else {}


def read_alias_services() -> dict[str, Any]:
    data = read_json(config_path("candidate", ALIAS_SERVICES_FILENAME), default={})
    return data if isinstance(data, dict) else {}


def read_physical_interfaces() -> list[str]:
    data = read_json(PHYSICAL_INTERFACES, default={})
    items = data.get("physical_interfaces", []) if isinstance(data, dict) else []
    names: list[str] = []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
            elif isinstance(item, str):
                names.append(item)
    return names


@contextmanager
def config_lock():
    path = config_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
