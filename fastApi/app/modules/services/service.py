"""Lógica de negocio FastAPI para Services."""

from __future__ import annotations

import subprocess
from typing import Any

from fastapi import HTTPException, status

from modules.services import repository

CATALOG: dict[str, dict[str, str]] = {
    "dnsmasq": {"service_name": "dnsmasq", "unit": "dnsmasq", "checker": "systemctl", "display_name": "dnsmasq", "configurable": "true", "default_enabled": "true"},
    "nftables": {"service_name": "nftables", "unit": "nftables", "checker": "systemctl", "display_name": "nftables", "configurable": "true", "default_enabled": "true"},
    "rsyslog": {"service_name": "rsyslog", "unit": "rsyslog", "checker": "systemctl", "display_name": "rsyslog", "configurable": "true", "default_enabled": "true"},
    "apache2": {"service_name": "apache2", "unit": "apache2", "checker": "systemctl", "display_name": "apache2", "configurable": "true", "default_enabled": "true"},
    "praesidium-fastapi": {"service_name": "praesidium-fastapi", "unit": "praesidium-fastapi", "checker": "systemctl", "display_name": "praesidium-fastapi", "configurable": "true", "default_enabled": "true"},
    "bpfilter": {"service_name": "bpfilter", "unit": "bpfilter", "checker": "systemctl", "display_name": "bpfilter", "configurable": "true", "default_enabled": "true"},
    "systemd-networkd": {"service_name": "systemd-networkd", "unit": "systemd-networkd", "checker": "systemctl", "display_name": "systemd-networkd", "configurable": "true", "default_enabled": "true"},
    "systemd-resolved": {"service_name": "systemd-resolved", "unit": "systemd-resolved", "checker": "systemctl", "display_name": "systemd-resolved", "configurable": "true", "default_enabled": "true"},
    "ssh": {"service_name": "ssh", "unit": "ssh", "checker": "systemctl", "display_name": "ssh", "configurable": "true", "default_enabled": "true"},
    "forwarding_ipv4": {"service_name": "forwarding_ipv4", "unit": "net.ipv4.ip_forward", "checker": "sysctl", "display_name": "Forwarding IPv4", "configurable": "true", "default_enabled": "true"},
    "forwarding_ipv6": {"service_name": "forwarding_ipv6", "unit": "net.ipv6.conf.all.forwarding", "checker": "sysctl", "display_name": "Forwarding IPv6", "configurable": "true", "default_enabled": "true"},
}
SYSCTL_ALLOWED = {"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """Lanza error estable status/error_code."""
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


def clean(value: Any) -> str:
    """Normaliza texto."""
    return str(value or "").strip()


def normalize_candidate(data: Any, *, strict: bool = True) -> dict[str, Any]:
    """Valida y normaliza candidate/services.json."""
    if not isinstance(data, dict):
        fail("SERVICES_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    if "services" in data and not isinstance(data.get("services"), dict):
        fail("SERVICES_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    if "services" not in data:
        if strict:
            fail("SERVICES_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        data = {**data, "services": {}}
    out = dict(data)
    services: dict[str, Any] = dict(out.get("services", {}))
    for service_name, definition in CATALOG.items():
        entry = services.get(service_name)
        if entry is None:
            entry = {"desired_enabled": definition["default_enabled"]}
        if not isinstance(entry, dict):
            fail("SERVICES_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        value = clean(entry.get("desired_enabled", definition["default_enabled"]))
        if value not in {"true", "false"}:
            value = "true" if definition["default_enabled"] == "true" else "false"
        services[service_name] = {"desired_enabled": value}
    out["services"] = services
    return out


def read_candidate_config() -> dict[str, Any]:
    """Lee candidate/services.json normalizado."""
    return normalize_candidate(repository.read_config_raw())


def catalog() -> dict[str, dict[str, Any]]:
    """Devuelve el catálogo fijo de services."""
    return {name: dict(definition) for name, definition in CATALOG.items()}


def validate_service_name(service_name: str) -> str:
    """Valida servicio conocido."""
    name = clean(service_name)
    if name not in CATALOG:
        fail("SERVICES_SERVICE_NOT_ALLOWED", status.HTTP_404_NOT_FOUND)
    return name


def validate_desired_enabled(value: Any) -> str:
    """Valida desired_enabled true/false string."""
    desired = clean(value).lower()
    if desired not in {"true", "false"}:
        fail("SERVICES_DESIRED_ENABLED_INVALID")
    return desired


def systemctl_runtime_status(unit: str) -> str:
    """Consulta systemctl is-active para una unidad permitida."""
    proc = subprocess.run(["/usr/bin/systemctl", "is-active", unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    value = clean(proc.stdout.splitlines()[0] if proc.stdout else "")
    return value or "unknown"


def sysctl_runtime_status(key: str) -> str:
    """Consulta runtime de forwarding con sysctl allowlist."""
    if key not in SYSCTL_ALLOWED:
        return "unknown"
    proc = subprocess.run(["/usr/sbin/sysctl", "-n", key], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    if proc.returncode != 0:
        return "unknown"
    value = clean(proc.stdout)
    if value == "1":
        return "active"
    if value == "0":
        return "inactive"
    return "unknown"


def runtime_status_for(definition: dict[str, str]) -> str:
    """Despacha runtime status según checker."""
    if definition.get("checker") == "sysctl":
        return sysctl_runtime_status(definition["unit"])
    return systemctl_runtime_status(definition["unit"])


def runtime_label(value: str) -> str:
    """Convierte runtime a etiqueta de tabla."""
    normalized = value.lower()
    if normalized == "active":
        return "ON"
    if normalized in {"unknown", "not-found"}:
        return "UNKNOWN"
    return "OFF"


def bool_label(value: str) -> str:
    """Convierte true/false a etiqueta simple."""
    return "Yes" if value == "true" else "No"


def runtime_statuses() -> dict[str, dict[str, str]]:
    """Devuelve runtime_status actual por servicio."""
    return {name: {"runtime_status": runtime_status_for(definition)} for name, definition in CATALOG.items()}


def rows() -> list[dict[str, Any]]:
    """Construye filas con candidate y runtime actual."""
    data = read_candidate_config()
    result: list[dict[str, Any]] = []
    for name, definition in CATALOG.items():
        runtime = runtime_status_for(definition)
        result.append({
            "service_name": definition["service_name"],
            "display_name": definition["display_name"],
            "runtime_status": runtime_label(runtime),
            "desired_enabled": data["services"][name]["desired_enabled"],
            "configurable": bool_label(definition["configurable"]),
        })
    return result


def get_service(service_name: str) -> dict[str, Any]:
    """Devuelve una fila individual enriquecida."""
    name = validate_service_name(service_name)
    for row in rows():
        if row["service_name"] == name:
            return row
    fail("SERVICES_SERVICE_NOT_ALLOWED", status.HTTP_404_NOT_FOUND)


def update_service(service_name: str, desired_enabled: Any) -> dict[str, Any]:
    """Actualiza desired_enabled en candidate sin aplicar systemd/sysctl."""
    name = validate_service_name(service_name)
    definition = CATALOG[name]
    if definition["configurable"] != "true":
        fail("SERVICES_SERVICE_NOT_CONFIGURABLE", status.HTTP_409_CONFLICT)
    desired = validate_desired_enabled(desired_enabled)
    with repository.config_lock():
        data = read_candidate_config()
        data["services"][name]["desired_enabled"] = desired
        repository.write_config(data)
    return {"success": True, "service_name": name, "desired_enabled": desired}
