"""Repositorio del módulo Nftables."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import fcntl

from storage.json_store import read_json, write_json
from storage.paths import STATE_DIR, config_path

FILENAME = "rules_nftables_human_viewer.json"
TABLES_CHAINS_FILENAME = "nftables_tables_chains.json"
ALIAS_IP_FILENAME = "alias_ip.json"
ALIAS_SERVICES_FILENAME = "alias_services.json"
ALL_INTERFACES = STATE_DIR / "interfaces" / "all_interfaces_list.json"


# ES: Devuelve el candidate controlado de reglas nftables.
# EN: Return the controlled nftables rules candidate path.
def config_file_path():
    return config_path("candidate", FILENAME)


# ES: Lee reglas nftables desde candidate.
# EN: Read nftables rules from candidate.
def read_config() -> dict[str, Any]:
    data = read_json(config_file_path(), default={})
    return data if isinstance(data, dict) else {}


# ES: Lee tablas/cadenas declaradas para validar rutas table/chain.
# EN: Read declared tables/chains to validate table/chain routes.
def read_tables_chains() -> dict[str, Any]:
    data = read_json(config_path("candidate", TABLES_CHAINS_FILENAME), default={})
    return data if isinstance(data, dict) else {}


# ES: Escribe tablas/cadenas nftables en candidate.
# EN: Write nftables tables/chains to candidate.
def write_tables_chains(data: dict[str, Any]) -> None:
    write_json(config_path("candidate", TABLES_CHAINS_FILENAME), data)


# ES: Escribe reglas nftables en candidate.
# EN: Write nftables rules to candidate.
def write_config(data: dict[str, Any]) -> None:
    write_json(config_file_path(), data)


# ES: Lee alias_ip candidate para validación delegada.
# EN: Read alias_ip candidate for delegated validation.
def read_alias_ip() -> dict[str, Any]:
    data = read_json(config_path("candidate", ALIAS_IP_FILENAME), default={})
    return data if isinstance(data, dict) else {}


# ES: Lee alias_services candidate para validación delegada.
# EN: Read alias_services candidate for delegated validation.
def read_alias_services() -> dict[str, Any]:
    data = read_json(config_path("candidate", ALIAS_SERVICES_FILENAME), default={})
    return data if isinstance(data, dict) else {}


# ES: Lee interfaces conocidas para validar meta.iifname/meta.oifname.
# EN: Read known interfaces to validate meta.iifname/meta.oifname.
def read_all_interfaces() -> list[str]:
    data = read_json(ALL_INTERFACES, default={})
    items = data.get("all_interfaces", []) if isinstance(data, dict) else []
    return [str(item) for item in items if isinstance(item, str) and item.strip()]


@contextmanager
# ES: Bloquea escrituras concurrentes sobre el candidate nftables.
# EN: Lock concurrent writes on the nftables candidate.
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


@contextmanager
# ES: Bloquea escrituras concurrentes sobre tablas/cadenas nftables.
# EN: Lock concurrent writes on nftables tables/chains.
def tables_chains_lock():
    path = config_path("candidate", TABLES_CHAINS_FILENAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
