"""Lógica FastAPI del módulo Dnsmasq/DHCP."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid
from modules.alias_ip.domain import SIMPLE_SECTION, find_entry_reference, resolve_deep_content, validate_mixed_ip_references
from modules.dnsmasq import repository

SECTIONS = ("dhcp", "dhcp_reservation")
INTERFACE_SECTIONS = ("ethernets", "bridges", "vlans", "wifis")
IP_FIELDS_SCOPE = ("range_start", "range_end", "gateway", "dns_primary", "dns_secondary", "ntp_server", "relay_local_ip", "relay_dest_server")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
LEASE_RE = re.compile(r"^[1-9][0-9]*[mhdw]$")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SCOPE_UUID_PREFIX = "scopes"
RESERVATION_UUID_PREFIX = "dhcpres"
IP_FIELDS_BY_SECTION = {
    "dhcp": IP_FIELDS_SCOPE,
    "dhcp_reservation": ("ip",),
}


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """Lanza error estable status/error_code. / Raise stable status/error_code."""
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


def clean(value: Any) -> str:
    """Normaliza escalares recibidos. / Normalize received scalar values."""
    return str(value or "").strip()


def config_shape(data: Any) -> dict[str, Any]:
    """Valida la forma base de candidate/dhcp.json."""
    if not isinstance(data, dict):
        fail("DHCP_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    if not isinstance(data.get("dhcp"), list):
        fail("DHCP_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    if not isinstance(data.get("dhcp_reservation"), list):
        fail("DHCP_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    for section in SECTIONS:
        for entry in data[section]:
            if not isinstance(entry, dict) or not isinstance(entry.get("rule"), dict):
                fail("DHCP_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    return data


def read_candidate_config() -> dict[str, Any]:
    """Lee candidate/dhcp.json validando shape."""
    return config_shape(repository.read_config_raw())


def rule_entries(data: dict[str, Any], section: str) -> list[dict[str, Any]]:
    """Devuelve reglas de una sección. / Return section rules."""
    return [entry["rule"] for entry in data[section]]


def existing_uuids(data: dict[str, Any]) -> set[str]:
    """Recoge UUIDs dnsmasq existentes. / Collect existing dnsmasq UUIDs."""
    return {str(rule.get("UUID")) for section in SECTIONS for rule in rule_entries(data, section) if rule.get("UUID")}


def normalize_id(value: Any, code: str = "DHCP_ID_INVALID") -> str:
    """Valida id numérico positivo. / Validate positive numeric id."""
    text = clean(value)
    if not text or not text.isdigit() or int(text) <= 0:
        fail(code)
    return str(int(text))


def next_id(data: dict[str, Any], section: str) -> str:
    """Calcula el siguiente id libre de la sección."""
    used = {int(rule.get("id")) for rule in rule_entries(data, section) if str(rule.get("id", "")).isdigit()}
    value = 1
    while value in used:
        value += 1
    return str(value)


def find_index_by_uuid(data: dict[str, Any], section: str, uuid: str) -> int | None:
    """Busca una entrada exclusivamente por UUID. / Find an entry exclusively by UUID."""
    target = clean(uuid)
    for idx, entry in enumerate(data[section]):
        if clean(entry.get("rule", {}).get("UUID")) == target:
            return idx
    return None


def normalize_name(value: Any) -> str:
    """Valida el nombre visible requerido. / Validate the required visible name."""
    name = clean(value)
    if not NAME_RE.fullmatch(name):
        fail("DHCP_NAME_INVALID")
    return name


def ensure_unique_name(data: dict[str, Any], section: str, name: str, ignore_uuid: str = "") -> None:
    """Impide nombres duplicados dentro de una sección. / Prevent duplicate names within one section."""
    for rule in rule_entries(data, section):
        if ignore_uuid and clean(rule.get("UUID")) == ignore_uuid:
            continue
        if clean(rule.get("name")) == name:
            fail("DHCP_NAME_DUPLICATE", status.HTTP_409_CONFLICT)


def entry_to_frontend(section: str, rule: dict[str, Any]) -> dict[str, Any]:
    """Traduce UUID Alias a name sólo para API/WebGUI; conserva literales. / Translate Alias UUID to name only for API/WebGUI; preserve literals."""
    visible = dict(rule)
    alias_data = repository.read_alias_ip()
    for field in IP_FIELDS_BY_SECTION.get(section, ()):
        value = visible.get(field)
        if not isinstance(value, str) or not value:
            continue
        alias_section, entry = find_entry_reference(alias_data, value)
        if alias_section == SIMPLE_SECTION and isinstance(entry, dict) and clean(entry.get("name")):
            visible[field] = clean(entry.get("name"))
    return visible


def frontend_config(data: dict[str, Any]) -> dict[str, Any]:
    """Construye configuración visible sin alterar candidate. / Build visible config without changing candidate."""
    return {
        section: [{"rule": entry_to_frontend(section, entry["rule"])} for entry in data[section]]
        for section in SECTIONS
    }


def read_frontend_config() -> dict[str, Any]:
    """Lee candidate y devuelve la vista pública. / Read candidate and return the public view."""
    return frontend_config(read_candidate_config())


def candidate_interfaces() -> list[str]:
    """Devuelve interfaces autorizadas desde candidate/interfaces.json."""
    data = repository.read_interfaces()
    network = data.get("network", {}) if isinstance(data, dict) else {}
    names: list[str] = []
    for section in INTERFACE_SECTIONS:
        block = network.get(section, {}) if isinstance(network, dict) else {}
        if isinstance(block, dict):
            names.extend(str(name) for name in block.keys() if str(name).strip())
    return sorted(dict.fromkeys(names))


def reservation_interfaces() -> list[str]:
    """Devuelve interfaces con scope server activo en candidate."""
    data = read_candidate_config()
    names: list[str] = []
    for rule in rule_entries(data, "dhcp"):
        if rule.get("enable", "true") == "true" and rule.get("mode", "server") == "server" and rule.get("interface"):
            names.append(str(rule["interface"]))
    return sorted(dict.fromkeys(names))


def ensure_interface(name: str) -> str:
    """Valida interface contra candidate, no contra Linux/state."""
    iface = clean(name)
    if not iface:
        fail("DHCP_INTERFACE_REQUIRED")
    if iface not in candidate_interfaces():
        fail("DHCP_INTERFACE_NOT_FOUND")
    return iface


def is_unicast_ipv4(ip: str) -> bool:
    """Comprueba IPv4 host usable para DHCPv4."""
    addr = ipaddress.IPv4Address(ip)
    bad_ranges = [
        ipaddress.IPv4Network("0.0.0.0/8"),
        ipaddress.IPv4Network("127.0.0.0/8"),
        ipaddress.IPv4Network("169.254.0.0/16"),
        ipaddress.IPv4Network("224.0.0.0/4"),
        ipaddress.IPv4Network("240.0.0.0/4"),
    ]
    return not any(addr in network for network in bad_ranges)


def alias_object_for(value: Any, alias_data: dict[str, Any]) -> dict[str, Any] | None:
    """Devuelve alias_address referido, si el valor es referencia alias."""
    section, entry = find_entry_reference(alias_data, value)
    if section is None:
        return None
    if entry is None:
        fail("ALIAS_REFERENCE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    if section != SIMPLE_SECTION:
        fail("ALIAS_GROUP_NOT_ALLOWED")
    return entry


def effective_ipv4(value: Any, field: str, *, required: bool = False) -> tuple[str, Any]:
    """Valida un único valor IP literal o alias_address y devuelve IP efectiva + valor persistente."""
    # ES: generic_table serializa un único chip como lista; seguimos aceptando exactamente un valor.
    # EN: generic_table serializes one chip as a list; exactly one value remains allowed.
    if isinstance(value, list) and value:
        if len(value) != 1:
            fail("ONLY_ONE_IP_CIDR_OR_ALIAS_ALLOWED")
        value = value[0]
    if value in (None, "", []):
        if required:
            fail("DHCP_IPV4_REQUIRED")
        return "", ""
    alias_data = repository.read_alias_ip()
    try:
        validate_mixed_ip_references(alias_data, value, allow_groups=False, allow_multiple=False)
    except HTTPException as exc:
        raise exc
    alias_entry = alias_object_for(value, alias_data)
    stored: Any = value
    if alias_entry is not None:
        values = resolve_deep_content(alias_data, SIMPLE_SECTION, alias_entry)
        if len(values) != 1:
            fail("DHCP_ALIAS_ADDRESS_MUST_RESOLVE_ONE_IP")
        ip_text = values[0]
        stored = clean(alias_entry.get("UUID"))
    else:
        if not isinstance(value, str):
            fail("DHCP_IPV4_INVALID")
        ip_text = clean(value)
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        fail("DHCP_IPV4_INVALID")
    if not isinstance(addr, ipaddress.IPv4Address):
        fail("DHCP_IPV6_NOT_SUPPORTED")
    if not is_unicast_ipv4(str(addr)):
        fail("DHCP_IPV4_NOT_USABLE")
    return str(addr), stored


def validate_netmask(value: Any, *, required: bool = False) -> str:
    """Valida netmask IPv4 contigua hardcodeada."""
    text = clean(value)
    if not text:
        if required:
            fail("DHCP_NETMASK_REQUIRED")
        return ""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        fail("DHCP_NETMASK_INVALID")
    if not isinstance(addr, ipaddress.IPv4Address):
        fail("DHCP_NETMASK_INVALID")
    bits = f"{int(addr):032b}"
    if "01" in bits:
        fail("DHCP_NETMASK_NOT_CONTIGUOUS")
    return str(addr)


def netmask_prefix(netmask: str) -> int:
    """Cuenta bits de red de una máscara."""
    return f"{int(ipaddress.IPv4Address(netmask)):032b}".count("1")


def network_for(gateway: str, netmask: str) -> ipaddress.IPv4Network:
    """Calcula red IPv4 desde gateway/netmask."""
    prefix = netmask_prefix(netmask)
    return ipaddress.IPv4Network(f"{gateway}/{prefix}", strict=False)


def is_network_or_broadcast(ip: str, gateway: str, netmask: str) -> bool:
    """Detecta dirección de red o broadcast."""
    network = network_for(gateway, netmask)
    addr = ipaddress.IPv4Address(ip)
    return addr == network.network_address or addr == network.broadcast_address


def range_contains(ip: str, start: str, end: str) -> bool:
    """Comprueba si una IP está dentro de un rango."""
    addr = int(ipaddress.IPv4Address(ip))
    return int(ipaddress.IPv4Address(start)) <= addr <= int(ipaddress.IPv4Address(end))


def ranges_overlap(a: dict[str, str], b: dict[str, Any]) -> bool:
    """Detecta solape entre dos rangos server."""
    return int(ipaddress.IPv4Address(a["range_start"])) <= int(ipaddress.IPv4Address(str(b["range_end"]))) and int(ipaddress.IPv4Address(str(b["range_start"]))) <= int(ipaddress.IPv4Address(a["range_end"]))


def lease_time(value: Any) -> str:
    """Valida lease_time dnsmasq."""
    text = clean(value)
    if not text:
        return "12h"
    if not LEASE_RE.fullmatch(text):
        fail("DHCP_LEASE_TIME_INVALID")
    return text


def normalize_enable(value: Any) -> str:
    """Valida checkbox enable."""
    text = clean(value if value is not None else "true").lower()
    if text not in {"true", "false"}:
        fail("DHCP_ENABLE_INVALID")
    return text


def normalize_mode(value: Any) -> str:
    """Valida modo DHCP."""
    text = clean(value if value is not None else "server").lower()
    if text not in {"server", "relay"}:
        fail("DHCP_MODE_INVALID")
    return text


def validate_scope_rule(rule: dict[str, Any], data: dict[str, Any], *, rule_id: str | None = None) -> dict[str, Any]:
    """Valida y normaliza una fila dhcp server/relay."""
    rid = normalize_id(rule_id if rule_id is not None else rule.get("id", next_id(data, "dhcp")))
    enable = normalize_enable(rule.get("enable", "true"))
    mode = normalize_mode(rule.get("mode", "server"))
    iface = ensure_interface(rule.get("interface", ""))
    normalized: dict[str, Any] = {
        "id": rid,
        "name": normalize_name(rule.get("name")),
        "enable": enable,
        "mode": mode,
        "interface": iface,
        "range_start": "",
        "range_end": "",
        "lease_time": "",
        "gateway": "",
        "netmask": "",
        "dns_primary": "",
        "dns_secondary": "",
        "ntp_server": "",
        "relay_local_ip": "",
        "relay_dest_server": "",
    }
    effective: dict[str, str] = {}
    if mode == "server":
        if clean(rule.get("relay_local_ip")) or clean(rule.get("relay_dest_server")):
            fail("DHCP_SERVER_RELAY_FIELDS_NOT_ALLOWED")
        for field in ("range_start", "range_end", "gateway"):
            effective[field], normalized[field] = effective_ipv4(rule.get(field), field, required=(enable == "true"))
        normalized["netmask"] = validate_netmask(rule.get("netmask"), required=(enable == "true"))
        normalized["lease_time"] = lease_time(rule.get("lease_time"))
        for field in ("dns_primary", "dns_secondary", "ntp_server"):
            effective[field], normalized[field] = effective_ipv4(rule.get(field), field, required=False)
        if enable == "true":
            if netmask_prefix(normalized["netmask"]) > 30:
                fail("DHCP_NETMASK_TOO_SMALL")
            if int(ipaddress.IPv4Address(effective["range_start"])) > int(ipaddress.IPv4Address(effective["range_end"])):
                fail("DHCP_RANGE_START_AFTER_END")
            network = network_for(effective["gateway"], normalized["netmask"])
            for field in ("gateway", "range_start", "range_end"):
                if ipaddress.IPv4Address(effective[field]) not in network:
                    fail("DHCP_FIELD_OUTSIDE_SCOPE_NETWORK")
                if is_network_or_broadcast(effective[field], effective["gateway"], normalized["netmask"]):
                    fail("DHCP_FIELD_NETWORK_OR_BROADCAST")
            if range_contains(effective["gateway"], effective["range_start"], effective["range_end"]):
                fail("DHCP_GATEWAY_INSIDE_RANGE")
            for field in ("dns_primary", "dns_secondary", "ntp_server"):
                if effective.get(field) and is_network_or_broadcast(effective[field], effective["gateway"], normalized["netmask"]):
                    fail("DHCP_FIELD_NETWORK_OR_BROADCAST")
    else:
        for field in ("range_start", "range_end", "gateway", "netmask", "dns_primary", "dns_secondary", "ntp_server"):
            if clean(rule.get(field)):
                fail("DHCP_RELAY_SCOPE_FIELDS_NOT_ALLOWED")
        effective["relay_local_ip"], normalized["relay_local_ip"] = effective_ipv4(rule.get("relay_local_ip"), "relay_local_ip", required=(enable == "true"))
        effective["relay_dest_server"], normalized["relay_dest_server"] = effective_ipv4(rule.get("relay_dest_server"), "relay_dest_server", required=(enable == "true"))
        if enable == "true" and effective["relay_local_ip"] == effective["relay_dest_server"]:
            fail("DHCP_RELAY_IPS_EQUAL")
    if enable == "true":
        compare = dict(normalized)
        compare.update({key: value for key, value in effective.items() if value})
        for other in rule_entries(data, "dhcp"):
            if str(other.get("id", "")) == rid or other.get("enable", "true") != "true" or other.get("interface") != iface:
                continue
            if other.get("mode", "server") != mode:
                fail("DHCP_SCOPE_MODE_CONFLICT")
            if mode == "relay":
                fail("DHCP_RELAY_DUPLICATE_INTERFACE")
            if mode == "server" and other.get("range_start") and other.get("range_end"):
                other_start, _ = effective_ipv4(other.get("range_start"), "range_start", required=True)
                other_end, _ = effective_ipv4(other.get("range_end"), "range_end", required=True)
                if ranges_overlap(compare, {"range_start": other_start, "range_end": other_end}):
                    fail("DHCP_SCOPE_RANGE_OVERLAP")
    return normalized


def validate_mac(value: Any) -> str:
    """Valida MAC unicast de reserva."""
    text = clean(value).upper()
    if not MAC_RE.fullmatch(text):
        fail("DHCP_MAC_INVALID")
    if text in {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}:
        fail("DHCP_MAC_NOT_UNICAST")
    if int(text[:2], 16) & 1:
        fail("DHCP_MAC_NOT_UNICAST")
    return text


def validate_hostname(value: Any) -> str:
    """Valida hostname simple opcional."""
    text = clean(value)
    if not text:
        return ""
    if not HOSTNAME_RE.fullmatch(text):
        fail("DHCP_HOSTNAME_INVALID")
    return text


def scope_for_reservation(reservation: dict[str, Any], data: dict[str, Any], effective_ip: str) -> dict[str, Any] | None:
    """Busca scope server compatible para una reserva."""
    for scope in rule_entries(data, "dhcp"):
        if scope.get("enable", "true") != "true" or scope.get("mode", "server") != "server" or scope.get("interface") != reservation["interface"]:
            continue
        if not scope.get("gateway") or not scope.get("netmask"):
            continue
        gw_value, _ = effective_ipv4(scope.get("gateway"), "gateway", required=True)
        network = network_for(gw_value, str(scope["netmask"]))
        if ipaddress.IPv4Address(effective_ip) in network:
            return scope
    return None


def validate_reservation_rule(rule: dict[str, Any], data: dict[str, Any], *, rule_id: str | None = None) -> dict[str, Any]:
    """Valida y normaliza una reserva DHCP."""
    rid = normalize_id(rule_id if rule_id is not None else rule.get("id", next_id(data, "dhcp_reservation")))
    enable = normalize_enable(rule.get("enable", "true"))
    iface = ensure_interface(rule.get("interface", ""))
    effective_ip, stored_ip = effective_ipv4(rule.get("ip"), "ip", required=True)
    normalized: dict[str, Any] = {
        "id": rid,
        "name": normalize_name(rule.get("name")),
        "enable": enable,
        "interface": iface,
        "mac": validate_mac(rule.get("mac", "")),
        "ip": stored_ip,
        "hostname": validate_hostname(rule.get("hostname", "")),
        "lease_time": lease_time(rule.get("lease_time")),
    }
    if enable == "true":
        for other in rule_entries(data, "dhcp_reservation"):
            if str(other.get("id", "")) == rid or other.get("enable", "true") != "true":
                continue
            if str(other.get("mac", "")).upper() == normalized["mac"]:
                fail("DHCP_RESERVATION_MAC_DUPLICATE")
            other_ip, _ = effective_ipv4(other.get("ip"), "ip", required=True)
            if other.get("interface") == iface and other_ip == effective_ip:
                fail("DHCP_RESERVATION_IP_DUPLICATE")
            if normalized["hostname"] and str(other.get("hostname", "")).lower() == normalized["hostname"].lower():
                fail("DHCP_RESERVATION_HOSTNAME_DUPLICATE")
        scope = scope_for_reservation(normalized, data, effective_ip)
        if scope is None:
            fail("DHCP_RESERVATION_SCOPE_NOT_FOUND")
        gw_value, _ = effective_ipv4(scope.get("gateway"), "gateway", required=True)
        if is_network_or_broadcast(effective_ip, gw_value, str(scope["netmask"])):
            fail("DHCP_FIELD_NETWORK_OR_BROADCAST")
        if effective_ip == gw_value:
            fail("DHCP_RESERVATION_IP_IS_GATEWAY")
    return normalized


def set_uuid(rule: dict[str, Any], uuid: str) -> dict[str, Any]:
    """Inserta UUID junto al id para mantener JSON legible."""
    ordered: dict[str, Any] = {}
    for key, value in rule.items():
        ordered[key] = value
        if key == "id":
            ordered["UUID"] = uuid
    if "UUID" not in ordered:
        ordered["UUID"] = uuid
    return ordered


def list_scopes() -> list[dict[str, Any]]:
    """Lista scopes con nombres Alias visibles. / List scopes with visible Alias names."""
    return [entry_to_frontend("dhcp", rule) for rule in rule_entries(read_candidate_config(), "dhcp")]


def list_reservations() -> list[dict[str, Any]]:
    """Lista reservas con nombres Alias visibles. / List reservations with visible Alias names."""
    return [entry_to_frontend("dhcp_reservation", rule) for rule in rule_entries(read_candidate_config(), "dhcp_reservation")]


def get_scope(uuid: str) -> dict[str, Any]:
    """Obtiene un scope exclusivamente por UUID. / Get a scope exclusively by UUID."""
    data = read_candidate_config()
    idx = find_index_by_uuid(data, "dhcp", uuid)
    if idx is None:
        fail("DHCP_SCOPE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    return entry_to_frontend("dhcp", data["dhcp"][idx]["rule"])


def get_reservation(uuid: str) -> dict[str, Any]:
    """Obtiene una reserva exclusivamente por UUID. / Get a reservation exclusively by UUID."""
    data = read_candidate_config()
    idx = find_index_by_uuid(data, "dhcp_reservation", uuid)
    if idx is None:
        fail("DHCP_RESERVATION_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    return entry_to_frontend("dhcp_reservation", data["dhcp_reservation"][idx]["rule"])


def create_scope(rule: dict[str, Any]) -> dict[str, Any]:
    """Crea un scope con id mínimo libre y UUID centralizado. / Create a scope with smallest free id and centralized UUID."""
    with repository.config_lock():
        data = read_candidate_config()
        rid = next_id(data, "dhcp")
        normalized = validate_scope_rule({**rule, "id": rid}, data, rule_id=rid)
        ensure_unique_name(data, "dhcp", normalized["name"])
        uuid = generate_unique_internal_uuid(SCOPE_UUID_PREFIX, rid, existing_uuids(data))
        normalized = set_uuid(normalized, uuid)
        data["dhcp"].append({"rule": normalized})
        repository.write_config(data)
    return {"success": True, "action": "create", "section": "dhcp", "id": rid, "uuid": uuid, "updated": uuid}


def update_scope(uuid: str, rule: dict[str, Any]) -> dict[str, Any]:
    """Actualiza un scope por UUID preservando identidad. / Update a scope by UUID while preserving identity."""
    with repository.config_lock():
        data = read_candidate_config()
        idx = find_index_by_uuid(data, "dhcp", uuid)
        if idx is None:
            fail("DHCP_SCOPE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        existing = data["dhcp"][idx]["rule"]
        rid = normalize_id(existing.get("id"))
        existing_uuid = clean(existing.get("UUID"))
        merged = {**existing, **rule, "id": rid, "UUID": existing_uuid}
        normalized = validate_scope_rule(merged, data, rule_id=rid)
        ensure_unique_name(data, "dhcp", normalized["name"], existing_uuid)
        data["dhcp"][idx]["rule"] = set_uuid(normalized, existing_uuid)
        repository.write_config(data)
    return {"success": True, "action": "update", "section": "dhcp", "id": rid, "uuid": existing_uuid, "updated": existing_uuid}


def delete_scope(uuid: str) -> dict[str, Any]:
    """Borra un scope por UUID. / Delete a scope by UUID."""
    with repository.config_lock():
        data = read_candidate_config()
        idx = find_index_by_uuid(data, "dhcp", uuid)
        if idx is None:
            fail("DHCP_SCOPE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        rid = normalize_id(data["dhcp"][idx]["rule"].get("id"))
        stored_uuid = clean(data["dhcp"][idx]["rule"].get("UUID"))
        del data["dhcp"][idx]
        repository.write_config(data)
    return {"success": True, "action": "delete", "section": "dhcp", "id": rid, "uuid": stored_uuid, "deleted_id": stored_uuid}


def create_reservation(rule: dict[str, Any]) -> dict[str, Any]:
    """Crea una reserva con id mínimo libre y UUID centralizado. / Create a reservation with smallest free id and centralized UUID."""
    with repository.config_lock():
        data = read_candidate_config()
        rid = next_id(data, "dhcp_reservation")
        normalized = validate_reservation_rule({**rule, "id": rid}, data, rule_id=rid)
        ensure_unique_name(data, "dhcp_reservation", normalized["name"])
        uuid = generate_unique_internal_uuid(RESERVATION_UUID_PREFIX, rid, existing_uuids(data))
        normalized = set_uuid(normalized, uuid)
        data["dhcp_reservation"].append({"rule": normalized})
        repository.write_config(data)
    return {"success": True, "action": "create", "section": "dhcp_reservation", "id": rid, "uuid": uuid, "updated": uuid}


def update_reservation(uuid: str, rule: dict[str, Any]) -> dict[str, Any]:
    """Actualiza una reserva por UUID preservando identidad. / Update a reservation by UUID while preserving identity."""
    with repository.config_lock():
        data = read_candidate_config()
        idx = find_index_by_uuid(data, "dhcp_reservation", uuid)
        if idx is None:
            fail("DHCP_RESERVATION_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        existing = data["dhcp_reservation"][idx]["rule"]
        rid = normalize_id(existing.get("id"))
        existing_uuid = clean(existing.get("UUID"))
        merged = {**existing, **rule, "id": rid, "UUID": existing_uuid}
        normalized = validate_reservation_rule(merged, data, rule_id=rid)
        ensure_unique_name(data, "dhcp_reservation", normalized["name"], existing_uuid)
        data["dhcp_reservation"][idx]["rule"] = set_uuid(normalized, existing_uuid)
        repository.write_config(data)
    return {"success": True, "action": "update", "section": "dhcp_reservation", "id": rid, "uuid": existing_uuid, "updated": existing_uuid}


def delete_reservation(uuid: str) -> dict[str, Any]:
    """Borra una reserva por UUID. / Delete a reservation by UUID."""
    with repository.config_lock():
        data = read_candidate_config()
        idx = find_index_by_uuid(data, "dhcp_reservation", uuid)
        if idx is None:
            fail("DHCP_RESERVATION_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        rid = normalize_id(data["dhcp_reservation"][idx]["rule"].get("id"))
        stored_uuid = clean(data["dhcp_reservation"][idx]["rule"].get("UUID"))
        del data["dhcp_reservation"][idx]
        repository.write_config(data)
    return {"success": True, "action": "delete", "section": "dhcp_reservation", "id": rid, "uuid": stored_uuid, "deleted_id": stored_uuid}
