"""
Validación específica de interfaces bond.
Bond-specific interface validation.

ES: Este módulo complementa las validaciones genéricas de service.py. No valida
ni transforma campos IP/alias porque esos contratos ya viven en
validate_alias_fields() y validate_mixed_ip_references().

EN: This module complements the generic validations in service.py. It does not
validate or transform IP/alias fields because those contracts already live in
validate_alias_fields() and validate_mixed_ip_references().
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import HTTPException, status


BOND_MODES = {"balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb"}
LACP_RATES = {"slow", "fast"}
TRANSMIT_HASH_POLICIES = {"layer2", "layer3+4", "layer2+3", "encap2+3", "encap3+4"}
TRANSMIT_HASH_MODES = {"balance-xor", "802.3ad", "balance-tlb"}
AD_SELECT_VALUES = {"stable", "bandwidth", "count"}
ARP_VALIDATE_VALUES = {"none", "active", "backup", "all"}
ARP_ALL_TARGETS_VALUES = {"any", "all"}
FAIL_OVER_MAC_POLICIES = {"none", "active", "follow"}
PRIMARY_RESELECT_POLICIES = {"always", "better", "failure"}
PRIMARY_MODES = {"active-backup", "balance-tlb", "balance-alb"}
RESEND_IGMP_MODES = {"balance-rr", "active-backup", "balance-tlb", "balance-alb"}
LEARN_PACKET_MODES = {"balance-tlb", "balance-alb"}

MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
MAC_SPECIAL = {"permanent", "random", "stable", "stable-ssid", "preserve"}
COMMON_BOND_KEYS = {
    "UUID", "uuid", "name", "renderer", "interfaces", "dhcp4", "dhcp6", "addresses", "gateway4", "gateway6",
    "nameservers.addresses", "nameservers.search", "macaddress", "mtu", "optional", "accept-ra",
    "ipv6-privacy", "routes.to", "routes.via", "routes.metric", "routes", "dhcp-identifier",
    "dhcp4-overrides.use-dns", "dhcp4-overrides.use-routes", "dhcp4-overrides.send-hostname",
    "local", "remote", "peers.allowed-ips", "peers.endpoint", "routing-policy.from", "routing-policy.to",
    "dhcp4-overrides.use-hostname", "dhcp4-overrides.hostname", "dhcp6-overrides.use-dns",
    "dhcp6-overrides.use-routes", "link-local", "ipv6-address-generation", "ipv6-address-token",
}


def _text(rule: dict[str, Any], key: str) -> str:
    value = rule.get(key, "")
    if value is None:
        return ""
    return str(value).strip()


def _has(rule: dict[str, Any], key: str) -> bool:
    return key in rule and _text(rule, key) != ""


def _validate_plain_int(rule: dict[str, Any], key: str, error: str, minimum: int = 0) -> None:
    if not _has(rule, key):
        return
    value = _text(rule, key)
    if not value.isdigit() or int(value) < minimum:
        fail(error)
    rule[key] = str(int(value))


def _validate_bond_common_fields(rule: dict[str, Any]) -> None:
    for key in rule:
        if key in COMMON_BOND_KEYS or key.startswith("parameters."):
            continue
        fail("BOND_FIELD_NOT_SUPPORTED")
    _validate_plain_int(rule, "mtu", "BOND_MTU_INVALID", 1)
    _validate_plain_int(rule, "routes.metric", "BOND_ROUTE_METRIC_INVALID", 0)
    if _has(rule, "renderer") and _text(rule, "renderer") not in {"networkd", "NetworkManager"}:
        fail("BOND_RENDERER_INVALID")
    if _has(rule, "dhcp-identifier") and _text(rule, "dhcp-identifier") not in {"mac", "duid"}:
        fail("BOND_DHCP_IDENTIFIER_INVALID")
    if _has(rule, "macaddress"):
        mac = _text(rule, "macaddress")
        if mac.lower() not in MAC_SPECIAL and not MAC_RE.match(mac):
            fail("BOND_MACADDRESS_INVALID")
    if _has(rule, "dhcp4-overrides.hostname") and not HOST_RE.match(_text(rule, "dhcp4-overrides.hostname")):
        fail("BOND_DHCP4_HOSTNAME_INVALID")
    if _has(rule, "link-local"):
        items = _csv_items(rule["link-local"])
        if len(items) != len(set(items)) or any(item not in {"ipv4", "ipv6"} for item in items):
            fail("BOND_LINK_LOCAL_INVALID")
        rule["link-local"] = ",".join(items)
    if _has(rule, "nameservers.search"):
        items = _csv_items(rule["nameservers.search"])
        if not items or any(not HOST_RE.match(item) for item in items):
            fail("BOND_NAMESERVER_SEARCH_INVALID")
        rule["nameservers.search"] = ",".join(items)
    if _has(rule, "ipv6-address-generation") and _text(rule, "ipv6-address-generation") not in {"eui64", "stable-privacy"}:
        fail("BOND_IPV6_ADDRESS_GENERATION_INVALID")
    if _has(rule, "ipv6-address-token"):
        token = _text(rule, "ipv6-address-token")
        if _has(rule, "ipv6-address-generation") or not token or any(ch.isspace() for ch in token):
            fail("BOND_IPV6_ADDRESS_TOKEN_INVALID")
    if "routes" in rule and rule.get("routes") not in ("", None, []):
        routes = rule["routes"] if isinstance(rule["routes"], list) else [rule["routes"]]
        if not isinstance(routes, list) or not routes:
            fail("BOND_LEGACY_ROUTES_INVALID")
        for route in routes:
            if not isinstance(route, dict) or not str(route.get("to", "")).strip() or not str(route.get("via", "")).strip():
                fail("BOND_LEGACY_ROUTES_INVALID")
            if "metric" in route and str(route.get("metric", "")).strip() and not str(route.get("metric", "")).strip().isdigit():
                fail("BOND_LEGACY_ROUTES_INVALID")

SUPPORTED_BOND_PARAMETERS = {
    "ad-select",
    "all-members-active",
    "all-slaves-active",
    "arp-all-targets",
    "arp-interval",
    "arp-ip-targets",
    "arp-validate",
    "down-delay",
    "fail-over-mac-policy",
    "gratuitous-arp",
    "gratuitious-arp",
    "lacp-rate",
    "learn-packet-interval",
    "mii-monitor-interval",
    "min-links",
    "mode",
    "packets-per-member",
    "packets-per-slave",
    "primary",
    "primary-reselect-policy",
    "resend-igmp",
    "transmit-hash-policy",
    "up-delay",
}


def fail(detail: str, code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """ES: Falla con el contrato HTTP usado por el módulo interfaces. EN: Raise the HTTP contract used by interfaces."""
    raise HTTPException(status_code=code, detail=detail)


def _csv_items(value: Any) -> list[str]:
    """ES: Acepta CSV o lista sin alterar contratos de alias/IP. EN: Accept CSV or list without touching alias/IP contracts."""
    if isinstance(value, list):
        raw: list[str] = []
        for item in value:
            raw.extend(str(item).split(","))
    else:
        raw = str(value).split(",")
    return [item.strip() for item in raw if item.strip()]


def _parameter(rule: dict[str, Any], name: str) -> str:
    """ES: Lee parameters.<name> como texto normalizado. EN: Read parameters.<name> as normalized text."""
    value = rule.get(f"parameters.{name}", "")
    if value is None:
        return ""
    return str(value).strip()


def _has_parameter(rule: dict[str, Any], name: str) -> bool:
    """ES: Diferencia campo ausente de campo presente vacío. EN: Distinguish absent field from present empty field."""
    return f"parameters.{name}" in rule and _parameter(rule, name) != ""


def _integer_parameter(rule: dict[str, Any], name: str, error: str, minimum: int = 0, maximum: int | None = None) -> int | None:
    """ES: Valida parámetros numéricos que Netplan espera como escalares enteros. EN: Validate numeric Netplan scalar parameters."""
    if not _has_parameter(rule, name):
        return None
    value = _parameter(rule, name)
    if not value.isdigit():
        fail(error)
    number = int(value)
    if number < minimum or (maximum is not None and number > maximum):
        fail(error)
    # ES: Guardamos texto decimal para mantener el estilo actual de candidate JSON.
    # EN: Store decimal text to preserve the current candidate JSON style.
    rule[f"parameters.{name}"] = str(number)
    return number


def _boolean_parameter(rule: dict[str, Any], name: str, error: str) -> None:
    """ES: Normaliza booleanos de bonding a valores que el generador puede emitir. EN: Normalize bonding booleans."""
    if not _has_parameter(rule, name):
        return
    value = _parameter(rule, name).lower()
    if value not in {"true", "false"}:
        fail(error)
    # ES: Netplan espera un booleano YAML real en estos parámetros, no texto.
    # EN: Netplan expects a real YAML boolean for these parameters, not text.
    rule[f"parameters.{name}"] = value == "true"


def _select_parameter(rule: dict[str, Any], name: str, allowed: set[str], error: str) -> str:
    """ES: Valida enumeraciones de Netplan sin aceptar literales ajenos. EN: Validate Netplan enumerations."""
    value = _parameter(rule, name)
    if value and value not in allowed:
        fail(error)
    return value


def _defined_interface_names(config: dict[str, Any]) -> set[str]:
    """ES: Nombres declarados en candidate/interfaces.json. EN: Names declared in candidate/interfaces.json."""
    network = config.get("network", {}) if isinstance(config, dict) else {}
    names: set[str] = set()
    if isinstance(network, dict):
        for block in network.values():
            if isinstance(block, dict):
                names.update(str(name) for name in block.keys())
    return names


def _composition_members(config: dict[str, Any], *, current_bond: str) -> dict[str, str]:
    """
    ES: Devuelve miembros ya consumidos por composiciones L2 para impedir que una
    interfaz física termine simultáneamente en bridge y bond. Si estamos editando
    el propio bond, sus miembros actuales se ignoran para permitir PATCH idempotente.
    EN: Return members already consumed by L2 compositions so one physical interface
    cannot be simultaneously enslaved by a bridge and a bond. Members of the bond
    currently being edited are ignored to allow idempotent PATCH operations.
    """
    network = config.get("network", {}) if isinstance(config, dict) else {}
    used: dict[str, str] = {}
    if not isinstance(network, dict):
        return used
    for bridge_name, bridge_cfg in (network.get("bridges") or {}).items():
        if isinstance(bridge_cfg, dict):
            for member in _csv_items(bridge_cfg.get("interfaces", "")):
                used.setdefault(member, f"bridge:{bridge_name}")
    for bond_name, bond_cfg in (network.get("bonds") or {}).items():
        if str(bond_name) == current_bond:
            continue
        if isinstance(bond_cfg, dict):
            for member in _csv_items(bond_cfg.get("interfaces", "")):
                used.setdefault(member, f"bond:{bond_name}")
    return used


def _normalize_bond_interfaces(rule: dict[str, Any], config: dict[str, Any]) -> list[str]:
    """
    ES: Valida y normaliza bonds.interfaces sin cambiar la validación genérica previa.
    EN: Validate and normalize bonds.interfaces without replacing prior generic validation.
    """
    members = _csv_items(rule.get("interfaces", ""))
    if not members:
        fail("BOND_INTERFACES_REQUIRED")
    if len(members) != len(set(members)):
        fail("BOND_INTERFACES_DUPLICATED")
    defined = _defined_interface_names(config)
    for member in members:
        if member not in defined:
            fail("BOND_INTERFACE_NOT_FOUND")
    bond_name = str(rule.get("name", "")).strip()
    if bond_name and bond_name in members:
        fail("BOND_SELF_REFERENCE")
    used = _composition_members(config, current_bond=bond_name)
    for member in members:
        if member in used:
            fail("BOND_INTERFACE_ALREADY_USED")
    # ES: El generador actual de Netplan espera CSV y llama split(',').
    # EN: The current Netplan generator expects CSV and calls split(',').
    rule["interfaces"] = ",".join(members)
    return members


def _normalize_arp_targets(rule: dict[str, Any]) -> list[str]:
    """ES: ARP targets de Netplan son sólo IPv4 y máximo 16. EN: Netplan ARP targets are IPv4-only, max 16."""
    if not _has_parameter(rule, "arp-ip-targets"):
        return []
    targets = _csv_items(rule.get("parameters.arp-ip-targets", ""))
    if not targets or len(targets) > 16:
        fail("BOND_ARP_IP_TARGETS_INVALID")
    for target in targets:
        try:
            ipaddress.IPv4Address(target)
        except ValueError:
            fail("BOND_ARP_IP_TARGETS_INVALID")
    # ES: Netplan espera secuencia; si llega CSV, guardamos lista para que YAML emita sequence.
    # EN: Netplan expects a sequence; if CSV arrives, store a list so YAML emits a sequence.
    rule["parameters.arp-ip-targets"] = targets
    return targets


def _reject_unknown_bond_parameters(rule: dict[str, Any]) -> None:
    """ES: Evita parameters.* que Netplan no conoce para bonds. EN: Reject parameters.* unknown to Netplan bonds."""
    for key in rule:
        if not key.startswith("parameters."):
            continue
        parameter = key.split(".", 1)[1]
        if parameter not in SUPPORTED_BOND_PARAMETERS:
            fail("BOND_PARAMETER_NOT_SUPPORTED")


def validate_and_normalize_bond_rule(rule: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """
    ES: Complementa las validaciones genéricas para bonds antes de guardar candidate.

    Esta función es deliberadamente quirúrgica: no revisa IPs, rutas con alias,
    DNS con alias ni gateways porque validate_alias_fields() ya lo hizo en
    service.py. Aquí sólo se cubren contratos de bonding/Netplan y se normalizan
    valores que el generador actual necesita en un formato concreto.

    EN: Complement generic validations for bonds before storing candidate.

    This function is intentionally surgical: it does not inspect IPs, alias-based
    routes, alias-based DNS or gateways because validate_alias_fields() already
    handled them in service.py. It only covers bonding/Netplan contracts and
    normalizes values required by the current generator.
    """
    _validate_bond_common_fields(rule)
    members = _normalize_bond_interfaces(rule, config)
    _reject_unknown_bond_parameters(rule)

    mode = _select_parameter(rule, "mode", BOND_MODES, "BOND_MODE_INVALID") or "balance-rr"
    lacp_rate = _select_parameter(rule, "lacp-rate", LACP_RATES, "BOND_LACP_RATE_INVALID")
    if lacp_rate and mode != "802.3ad":
        fail("BOND_LACP_RATE_MODE_INVALID")

    transmit_hash = _select_parameter(rule, "transmit-hash-policy", TRANSMIT_HASH_POLICIES, "BOND_TRANSMIT_HASH_POLICY_INVALID")
    if transmit_hash and mode not in TRANSMIT_HASH_MODES:
        fail("BOND_TRANSMIT_HASH_POLICY_MODE_INVALID")

    ad_select = _select_parameter(rule, "ad-select", AD_SELECT_VALUES, "BOND_AD_SELECT_INVALID")
    if ad_select and mode != "802.3ad":
        fail("BOND_AD_SELECT_MODE_INVALID")

    _boolean_parameter(rule, "all-members-active", "BOND_ALL_MEMBERS_ACTIVE_INVALID")
    _boolean_parameter(rule, "all-slaves-active", "BOND_ALL_MEMBERS_ACTIVE_INVALID")

    miimon = _integer_parameter(rule, "mii-monitor-interval", "BOND_MII_MONITOR_INTERVAL_INVALID") or 0
    up_delay = _integer_parameter(rule, "up-delay", "BOND_UP_DELAY_INVALID")
    down_delay = _integer_parameter(rule, "down-delay", "BOND_DOWN_DELAY_INVALID")
    if up_delay is not None and up_delay > 0 and miimon <= 0:
        fail("BOND_UP_DELAY_REQUIRES_MII_MONITOR_INTERVAL")
    if down_delay is not None and down_delay > 0 and miimon <= 0:
        fail("BOND_DOWN_DELAY_REQUIRES_MII_MONITOR_INTERVAL")

    _integer_parameter(rule, "min-links", "BOND_MIN_LINKS_INVALID")
    arp_interval = _integer_parameter(rule, "arp-interval", "BOND_ARP_INTERVAL_INVALID") or 0
    arp_targets = _normalize_arp_targets(rule)
    if arp_interval > 0 and not arp_targets:
        fail("BOND_ARP_IP_TARGETS_REQUIRED")
    if arp_interval == 0 and arp_targets:
        fail("BOND_ARP_IP_TARGETS_REQUIRE_ARP_INTERVAL")

    arp_validate = _select_parameter(rule, "arp-validate", ARP_VALIDATE_VALUES, "BOND_ARP_VALIDATE_INVALID")
    if arp_validate and arp_validate != "none" and (arp_interval <= 0 or not arp_targets):
        fail("BOND_ARP_VALIDATE_REQUIRES_ARP_MONITOR")

    arp_all_targets = _select_parameter(rule, "arp-all-targets", ARP_ALL_TARGETS_VALUES, "BOND_ARP_ALL_TARGETS_INVALID")
    if arp_all_targets and (mode != "active-backup" or not arp_validate or arp_validate == "none" or arp_interval <= 0 or not arp_targets):
        fail("BOND_ARP_ALL_TARGETS_REQUIRES_ACTIVE_BACKUP_ARP_VALIDATE")

    _select_parameter(rule, "fail-over-mac-policy", FAIL_OVER_MAC_POLICIES, "BOND_FAIL_OVER_MAC_POLICY_INVALID")

    gratuitous_arp = _integer_parameter(rule, "gratuitous-arp", "BOND_GRATUITOUS_ARP_INVALID", 1, 255)
    gratuitious_arp = _integer_parameter(rule, "gratuitious-arp", "BOND_GRATUITOUS_ARP_INVALID", 1, 255)
    if (gratuitous_arp is not None or gratuitious_arp is not None) and mode != "active-backup":
        fail("BOND_GRATUITOUS_ARP_MODE_INVALID")

    packets_per_member = _integer_parameter(rule, "packets-per-member", "BOND_PACKETS_PER_MEMBER_INVALID", 0, 65535)
    packets_per_slave = _integer_parameter(rule, "packets-per-slave", "BOND_PACKETS_PER_MEMBER_INVALID", 0, 65535)
    if (packets_per_member is not None or packets_per_slave is not None) and mode != "balance-rr":
        fail("BOND_PACKETS_PER_MEMBER_MODE_INVALID")

    primary = _parameter(rule, "primary")
    if primary:
        if primary not in members:
            fail("BOND_PRIMARY_INVALID")
        if mode not in PRIMARY_MODES:
            fail("BOND_PRIMARY_MODE_INVALID")

    primary_reselect = _select_parameter(rule, "primary-reselect-policy", PRIMARY_RESELECT_POLICIES, "BOND_PRIMARY_RESELECT_POLICY_INVALID")
    if primary_reselect and (not primary or mode not in PRIMARY_MODES):
        fail("BOND_PRIMARY_RESELECT_POLICY_MODE_INVALID")

    resend_igmp = _integer_parameter(rule, "resend-igmp", "BOND_RESEND_IGMP_INVALID", 0, 255)
    if resend_igmp is not None and mode not in RESEND_IGMP_MODES:
        fail("BOND_RESEND_IGMP_MODE_INVALID")

    learn_packet_interval = _integer_parameter(rule, "learn-packet-interval", "BOND_LEARN_PACKET_INTERVAL_INVALID", 1, 0x7fffffff)
    if learn_packet_interval is not None and mode not in LEARN_PACKET_MODES:
        fail("BOND_LEARN_PACKET_INTERVAL_MODE_INVALID")

    return rule
