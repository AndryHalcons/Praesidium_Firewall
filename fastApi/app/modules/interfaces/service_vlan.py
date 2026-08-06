"""Validación específica de VLANs, complementaria a service.py.
VLAN-specific validation, complementary to service.py.

ES: validate_and_normalize_vlan_rule() en service.py sigue siendo autoridad para
id/link/name. Este módulo añade sólo checks extra que evitan YAML Netplan malo.
EN: validate_and_normalize_vlan_rule() in service.py remains authoritative for
id/link/name. This module only adds extra checks preventing bad Netplan YAML.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException, status


def fail(detail: str, code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    raise HTTPException(status_code=code, detail=detail)


MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
MAC_SPECIAL = {"permanent", "random", "stable", "stable-ssid", "preserve"}

COMMON_INTERFACE_KEYS = {
    "UUID", "uuid", "name", "renderer", "dhcp4", "dhcp6", "addresses", "gateway4", "gateway6",
    "nameservers.addresses", "nameservers.search", "macaddress", "mtu", "optional", "accept-ra",
    "ipv6-privacy", "routes.to", "routes.via", "routes.metric", "routes", "dhcp-identifier",
    "dhcp4-overrides.use-dns", "dhcp4-overrides.use-routes", "dhcp4-overrides.send-hostname",
    "local", "remote", "peers.allowed-ips", "peers.endpoint", "routing-policy.from", "routing-policy.to",
    "dhcp4-overrides.use-hostname", "dhcp4-overrides.hostname", "dhcp6-overrides.use-dns",
    "dhcp6-overrides.use-routes", "link-local", "ipv6-address-generation", "ipv6-address-token",
}
DOMAIN_RE = HOST_RE


def _validate_csv_enum(rule: dict[str, Any], key: str, allowed: set[str], error: str) -> None:
    if not _has(rule, key):
        return
    items = _csv_items(rule[key])
    if len(items) != len(set(items)) or any(item not in allowed for item in items):
        fail(error)
    rule[key] = ",".join(items)


def _validate_nameserver_search(rule: dict[str, Any], prefix: str) -> None:
    if not _has(rule, "nameservers.search"):
        return
    items = _csv_items(rule["nameservers.search"])
    if not items or any(not DOMAIN_RE.match(item) for item in items):
        fail(f"{prefix}_NAMESERVER_SEARCH_INVALID")
    rule["nameservers.search"] = ",".join(items)


def _validate_legacy_routes_shape(rule: dict[str, Any], prefix: str) -> None:
    if "routes" not in rule or rule.get("routes") in ("", None, []):
        return
    routes = rule["routes"] if isinstance(rule["routes"], list) else [rule["routes"]]
    if not isinstance(routes, list) or not routes:
        fail(f"{prefix}_LEGACY_ROUTES_INVALID")
    for route in routes:
        if not isinstance(route, dict):
            fail(f"{prefix}_LEGACY_ROUTES_INVALID")
        if not str(route.get("to", "")).strip() or not str(route.get("via", "")).strip():
            fail(f"{prefix}_LEGACY_ROUTES_INVALID")
        if "metric" in route and str(route.get("metric", "")).strip() and not str(route.get("metric", "")).strip().isdigit():
            fail(f"{prefix}_LEGACY_ROUTES_INVALID")


def _validate_common_unknown_fields(rule: dict[str, Any], allowed: set[str], prefix: str) -> None:
    for key in rule:
        if key in allowed:
            continue
        if key.startswith("access-points.") and "access-points.*" in allowed:
            continue
        if key.startswith("parameters.") and "parameters.*" in allowed:
            continue
        fail(f"{prefix}_FIELD_NOT_SUPPORTED")


def _text(rule: dict[str, Any], key: str) -> str:
    value = rule.get(key, "")
    if value is None:
        return ""
    return str(value).strip()


def _has(rule: dict[str, Any], key: str) -> bool:
    return key in rule and _text(rule, key) != ""


def _csv_items(value: Any) -> list[str]:
    if isinstance(value, list):
        raw: list[str] = []
        for item in value:
            raw.extend(str(item).split(","))
    else:
        raw = str(value).split(",")
    return [item.strip() for item in raw if item.strip()]


def _bool_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def _validate_int(rule: dict[str, Any], key: str, error: str, minimum: int = 0, maximum: int | None = None) -> int | None:
    if not _has(rule, key):
        return None
    value = _text(rule, key)
    if not value.isdigit():
        fail(error)
    number = int(value)
    if number < minimum or (maximum is not None and number > maximum):
        fail(error)
    rule[key] = str(number)
    return number


def _validate_bool(rule: dict[str, Any], key: str, error: str) -> None:
    if not _has(rule, key):
        return
    value = _bool_value(rule[key])
    if value is None:
        fail(error)
    # ES: Se conserva el formato string histórico del candidate para campos existentes.
    # EN: Preserve the historical candidate string format for existing fields.
    rule[key] = "True" if value else "False"


def _validate_mac_value(value: str, error: str, *, allow_special: bool = True) -> None:
    lower = value.lower()
    if allow_special and lower in MAC_SPECIAL:
        return
    if not MAC_RE.match(value):
        fail(error)


def _validate_common_netplan_scalars(rule: dict[str, Any], prefix: str) -> None:
    # ES: Complemento seguro: no toca IPs ni alias; sólo escalares que el generador emite y antes ignoraba si eran inválidos.
    # EN: Safe complement: does not touch IPs or aliases; only scalars emitted by the generator and previously ignored if invalid.
    _validate_int(rule, "mtu", f"{prefix}_MTU_INVALID", 1)
    _validate_int(rule, "routes.metric", f"{prefix}_ROUTE_METRIC_INVALID", 0)
    if _has(rule, "macaddress"):
        _validate_mac_value(_text(rule, "macaddress"), f"{prefix}_MACADDRESS_INVALID")
    if _has(rule, "dhcp4-overrides.hostname") and not HOST_RE.match(_text(rule, "dhcp4-overrides.hostname")):
        fail(f"{prefix}_DHCP4_HOSTNAME_INVALID")
    if _has(rule, "renderer"):
        allowed_renderer = {"networkd", "NetworkManager", "sriov"} if prefix == "VLAN" else {"networkd", "NetworkManager"}
        if _text(rule, "renderer") not in allowed_renderer:
            fail(f"{prefix}_RENDERER_INVALID")
    if _has(rule, "dhcp-identifier") and _text(rule, "dhcp-identifier") not in {"mac", "duid"}:
        fail(f"{prefix}_DHCP_IDENTIFIER_INVALID")
    _validate_csv_enum(rule, "link-local", {"ipv4", "ipv6"}, f"{prefix}_LINK_LOCAL_INVALID")
    _validate_nameserver_search(rule, prefix)
    _validate_legacy_routes_shape(rule, prefix)
    if _has(rule, "ipv6-address-generation") and _text(rule, "ipv6-address-generation") not in {"eui64", "stable-privacy"}:
        fail(f"{prefix}_IPV6_ADDRESS_GENERATION_INVALID")
    if _has(rule, "ipv6-address-token"):
        token = _text(rule, "ipv6-address-token")
        if _has(rule, "ipv6-address-generation") or not token or any(ch.isspace() for ch in token):
            fail(f"{prefix}_IPV6_ADDRESS_TOKEN_INVALID")



def _allowed_vlan_links(config: dict[str, Any]) -> set[str]:
    network = config.get("network", {}) if isinstance(config, dict) else {}
    names: set[str] = set()
    if isinstance(network, dict):
        for section in ("ethernets", "bonds", "bridges"):
            block = network.get(section, {})
            if isinstance(block, dict):
                names.update(str(name) for name in block.keys())
    return names


def validate_and_normalize_vlan_netplan_rule(rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """ES/EN: Complementa VLAN tras la validación VLAN existente de service.py."""
    _validate_common_unknown_fields(rule, COMMON_INTERFACE_KEYS | {"id", "link", "parameters.*"}, "VLAN")
    _validate_common_netplan_scalars(rule, "VLAN")
    link = _text(rule, "link")
    if link and link not in _allowed_vlan_links(config):
        fail("VLAN_LINK_TYPE_INVALID")
    for key in rule:
        if key.startswith("parameters."):
            fail("VLAN_PARAMETER_NOT_SUPPORTED")
    return rule
