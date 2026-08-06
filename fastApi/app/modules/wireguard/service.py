"""Lógica de negocio FastAPI para WireGuard."""

from __future__ import annotations

import ipaddress
import io
import re
import struct
import subprocess
import sys
import zipfile
import zlib
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid
from modules.alias_ip.domain import find_entry_reference as find_ip_reference, mixed_reference_items as ip_mixed_reference_items, resolve_deep_content as resolve_ip_deep_content, single_domain_or_ip_check, single_host_check, single_ip_port_check, single_net_check, validate_mixed_ip_references
from modules.alias_services.domain import find_entry_reference as find_service_reference, mixed_reference_items as service_mixed_reference_items, resolve_deep_content as resolve_service_deep_content, single_port_check
from modules.wireguard import repository

SECTIONS = ("site_to_site", "remote_access", "remote_clients")
API_TO_SECTION = {
    "site-to-site": "site_to_site",
    "remote-access": "remote_access",
    "remote-clients": "remote_clients",
}
SECTION_TO_API = {value: key for key, value in API_TO_SECTION.items()}
PREFIX = {"site_to_site": "wg-s2s", "remote_access": "wg-ra", "remote_clients": "wg-client"}
SECRET_FIELDS = {"private_key", "client_private_key"}
KEY_FIELDS = {"private_key", "remote_public_key", "client_private_key", "client_public_key"}
COMMON_ALLOWED = {"name", "enabled"}
ALLOWED_FIELDS = {
    "site_to_site": COMMON_ALLOWED | {"interface", "local_tunnel_ip", "remote_tunnel_ip", "local_networks", "remote_networks", "listen_port", "remote_endpoint", "private_key", "remote_public_key", "keepalive", "mtu"},
    "remote_access": COMMON_ALLOWED | {"interface", "server_vpn_ip", "vpn_network", "listen_port", "public_endpoint", "internal_networks", "dns", "private_key", "mtu"},
    "remote_clients": COMMON_ALLOWED | {"vpn", "client_vpn_ip", "client_private_key", "client_public_key", "allowed_ips", "keepalive"},
}
ALIAS_IP_FIELDS = {
    "site_to_site": {"local_tunnel_ip", "remote_tunnel_ip", "local_networks", "remote_networks"},
    "remote_access": {"server_vpn_ip", "vpn_network", "public_endpoint", "internal_networks", "dns"},
    "remote_clients": set(),
}
ALIAS_SERVICE_FIELDS = {
    "site_to_site": {"listen_port"},
    "remote_access": {"listen_port"},
    "remote_clients": set(),
}
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """Lanza error estable status/error_code."""
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


def clean(value: Any) -> str:
    """Normaliza escalares de entrada."""
    return str(value or "").strip()


def config_shape(data: Any) -> dict[str, Any]:
    """Valida la forma base de candidate/wireguard.json."""
    if not isinstance(data, dict):
        fail("WIREGUARD_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    out: dict[str, Any] = {}
    for section in SECTIONS:
        value = data.get(section, {})
        if value in ([], None):
            value = {}
        if not isinstance(value, dict):
            fail("WIREGUARD_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        for name, entry in value.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                fail("WIREGUARD_CONFIG_MALFORMED", status.HTTP_500_INTERNAL_SERVER_ERROR)
        out[section] = value
    return out


def read_config() -> dict[str, Any]:
    """Lee candidate/wireguard.json validando shape."""
    return config_shape(repository.read_config_raw())


def mask_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Enmascara secretos en respuestas de listado/consulta."""
    out = dict(entry)
    for field in SECRET_FIELDS:
        if clean(out.get(field)):
            out[field] = "********"
    return out


def _reference_value_to_storage(alias_data: dict[str, Any], item: Any, finder: Any) -> str:
    """Convierte una referencia Alias visible/objeto/UUID a UUID; conserva literales."""
    _, target = finder(alias_data, item)
    if target:
        return clean(target.get("UUID"))
    if isinstance(item, dict):
        return clean(item.get("UUID") or item.get("uuid") or item.get("name"))
    return clean(item)


def _reference_value_to_frontend(alias_data: dict[str, Any], item: Any, finder: Any) -> str:
    """Convierte un UUID Alias almacenado a name visible; conserva literales."""
    _, target = finder(alias_data, item)
    if target:
        return clean(target.get("name"))
    if isinstance(item, dict):
        return clean(item.get("name") or item.get("UUID") or item.get("uuid"))
    return clean(item)


def alias_fields_to_storage(section: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Normaliza campos WireGuard susceptibles de Alias a UUID+literals."""
    stored = dict(entry)
    alias_ip = repository.read_alias_ip()
    alias_services = repository.read_alias_services()
    for field in ALIAS_IP_FIELDS.get(section, set()):
        if field in stored:
            stored[field] = [_reference_value_to_storage(alias_ip, item, find_ip_reference) for item in ip_mixed_reference_items(stored[field])]
    for field in ALIAS_SERVICE_FIELDS.get(section, set()):
        if field in stored:
            stored[field] = [_reference_value_to_storage(alias_services, item, find_service_reference) for item in service_mixed_reference_items(stored[field])]
    return stored


def alias_fields_to_frontend(section: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Traduce UUIDs Alias de storage a names visibles para API/WebGUI."""
    visible = dict(entry)
    alias_ip = repository.read_alias_ip()
    alias_services = repository.read_alias_services()
    for field in ALIAS_IP_FIELDS.get(section, set()):
        if field in visible:
            visible[field] = [_reference_value_to_frontend(alias_ip, item, find_ip_reference) for item in ip_mixed_reference_items(visible[field])]
    for field in ALIAS_SERVICE_FIELDS.get(section, set()):
        if field in visible:
            visible[field] = [_reference_value_to_frontend(alias_services, item, find_service_reference) for item in service_mixed_reference_items(visible[field])]
    return visible


def masked_config(data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Devuelve configuración visible y enmascarada para usuarios API/WebGUI."""
    data = read_config() if data is None else data
    return {
        section: {name: mask_entry(alias_fields_to_frontend(section, entry)) for name, entry in data[section].items()}
        for section in SECTIONS
    }


def section_from_api(token: str) -> str:
    """Convierte nombre público de sección al nombre JSON."""
    section = API_TO_SECTION.get(token)
    if not section:
        fail("WIREGUARD_SECTION_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    return section


def validate_name(name: Any) -> str:
    """Valida nombre interno de entrada."""
    value = clean(name)
    if not value or not NAME_RE.fullmatch(value):
        fail("WIREGUARD_NAME_INVALID")
    return value


def make_name(config: dict[str, Any], section: str) -> str:
    """Genera el siguiente nombre estable por sección."""
    index = 0
    prefix = PREFIX[section]
    while f"{prefix}{index}" in config[section]:
        index += 1
    return f"{prefix}{index}"


def site_to_site_next_id(config: dict[str, Any]) -> str:
    """Devuelve el menor ID site-to-site libre empezando por 1."""
    used: set[int] = set()
    for entry in config.get("site_to_site", {}).values():
        if not isinstance(entry, dict):
            continue
        text = clean(entry.get("id"))
        if text.isdigit() and int(text) > 0:
            used.add(int(text))
    candidate = 1
    while candidate in used:
        candidate += 1
    return str(candidate)


def site_to_site_existing_uuids(config: dict[str, Any]) -> set[str]:
    """Devuelve UUIDs existentes de WireGuard site-to-site."""
    return {
        clean(entry.get("UUID"))
        for entry in config.get("site_to_site", {}).values()
        if isinstance(entry, dict) and clean(entry.get("UUID"))
    }


def find_site_to_site_by_uuid(config: dict[str, Any], uuid: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    """Busca una entrada site-to-site exclusivamente por UUID."""
    clean_uuid = clean(uuid)
    entry = config.get("site_to_site", {}).get(clean_uuid)
    if isinstance(entry, dict) and clean(entry.get("UUID")) == clean_uuid:
        return clean_uuid, entry
    for key, candidate in config.get("site_to_site", {}).items():
        if isinstance(candidate, dict) and clean(candidate.get("UUID")) == clean_uuid:
            return str(key), candidate
    return None, None


def ensure_unique_site_to_site_name(config: dict[str, Any], name: str, ignore_uuid: str = "") -> None:
    """Evita nombres visibles duplicados en site-to-site."""
    for entry in config.get("site_to_site", {}).values():
        if not isinstance(entry, dict):
            continue
        if ignore_uuid and clean(entry.get("UUID")) == ignore_uuid:
            continue
        if clean(entry.get("name")) == name:
            fail("WIREGUARD_NAME_DUPLICATE", status.HTTP_409_CONFLICT)


def remote_access_next_id(config: dict[str, Any]) -> str:
    """Devuelve el menor ID remote-access libre empezando por 1."""
    used: set[int] = set()
    for entry in config.get("remote_access", {}).values():
        if not isinstance(entry, dict):
            continue
        text = clean(entry.get("id"))
        if text.isdigit() and int(text) > 0:
            used.add(int(text))
    candidate = 1
    while candidate in used:
        candidate += 1
    return str(candidate)


def remote_access_existing_uuids(config: dict[str, Any]) -> set[str]:
    """Devuelve UUIDs existentes de WireGuard remote-access."""
    return {
        clean(entry.get("UUID"))
        for entry in config.get("remote_access", {}).values()
        if isinstance(entry, dict) and clean(entry.get("UUID"))
    }


def find_remote_access_by_uuid(config: dict[str, Any], uuid: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    """Busca un servidor remote-access exclusivamente por UUID."""
    clean_uuid = clean(uuid)
    entry = config.get("remote_access", {}).get(clean_uuid)
    if isinstance(entry, dict) and clean(entry.get("UUID")) == clean_uuid:
        return clean_uuid, entry
    for key, candidate in config.get("remote_access", {}).items():
        if isinstance(candidate, dict) and clean(candidate.get("UUID")) == clean_uuid:
            return str(key), candidate
    return None, None


def ensure_unique_remote_access_name(config: dict[str, Any], name: str, ignore_uuid: str = "") -> None:
    """Evita nombres visibles duplicados en remote-access."""
    for entry in config.get("remote_access", {}).values():
        if not isinstance(entry, dict):
            continue
        if ignore_uuid and clean(entry.get("UUID")) == ignore_uuid:
            continue
        if clean(entry.get("name")) == name:
            fail("WIREGUARD_NAME_DUPLICATE", status.HTTP_409_CONFLICT)


def remote_client_next_id(config: dict[str, Any]) -> str:
    """Devuelve el menor ID remote-client libre empezando por 1."""
    used: set[int] = set()
    for entry in config.get("remote_clients", {}).values():
        if not isinstance(entry, dict):
            continue
        text = clean(entry.get("id"))
        if text.isdigit() and int(text) > 0:
            used.add(int(text))
    candidate = 1
    while candidate in used:
        candidate += 1
    return str(candidate)


def remote_client_existing_uuids(config: dict[str, Any]) -> set[str]:
    """Devuelve UUIDs existentes de clientes WireGuard."""
    return {
        clean(entry.get("UUID"))
        for entry in config.get("remote_clients", {}).values()
        if isinstance(entry, dict) and clean(entry.get("UUID"))
    }


def find_remote_client_by_uuid(config: dict[str, Any], uuid: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    """Busca un cliente WireGuard exclusivamente por UUID."""
    clean_uuid = clean(uuid)
    entry = config.get("remote_clients", {}).get(clean_uuid)
    if isinstance(entry, dict) and clean(entry.get("UUID")) == clean_uuid:
        return clean_uuid, entry
    for key, candidate in config.get("remote_clients", {}).items():
        if isinstance(candidate, dict) and clean(candidate.get("UUID")) == clean_uuid:
            return str(key), candidate
    return None, None


def ensure_unique_remote_client_name(config: dict[str, Any], name: str, ignore_uuid: str = "") -> None:
    """Evita nombres visibles duplicados entre clientes WireGuard."""
    for entry in config.get("remote_clients", {}).values():
        if not isinstance(entry, dict):
            continue
        if ignore_uuid and clean(entry.get("UUID")) == ignore_uuid:
            continue
        if clean(entry.get("name")) == name:
            fail("WIREGUARD_NAME_DUPLICATE", status.HTTP_409_CONFLICT)


def csv_items(value: Any) -> list[str]:
    """Divide CSV eliminando vacíos."""
    text = clean(value)
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


def parse_cidr(item: str, code: str, *, allow_default: bool = False) -> ipaddress._BaseNetwork | str:
    """Valida un CIDR IPv4/IPv6."""
    if allow_default and item == "default":
        return "default"
    if "/" not in item:
        fail(code)
    try:
        return ipaddress.ip_network(item, strict=False)
    except ValueError:
        fail(code)


def validate_csv_cidrs(value: Any, code: str, *, required: bool = False, allow_default: bool = False) -> list[ipaddress._BaseNetwork | str]:
    """Valida lista CSV de CIDRs."""
    items = csv_items(value)
    if required and not items:
        fail("WIREGUARD_REQUIRED_FIELD")
    return [parse_cidr(item, code, allow_default=allow_default) for item in items]


def validate_csv_ips(value: Any, code: str) -> None:
    """Valida lista CSV de IPs sin prefijo."""
    for item in csv_items(value):
        try:
            ipaddress.ip_address(item)
        except ValueError:
            fail(code)


def validate_port(value: Any, code: str = "WIREGUARD_PORT_INVALID") -> str:
    """Valida puerto 1-65535."""
    text = clean(value)
    if not text:
        return ""
    if not text.isdigit() or int(text) < 1 or int(text) > 65535:
        fail(code)
    return str(int(text))


def validate_int_range(value: Any, field: str, minimum: int, maximum: int) -> str:
    """Valida entero acotado opcional."""
    text = clean(value)
    if not text:
        return ""
    if not text.isdigit() or int(text) < minimum or int(text) > maximum:
        fail(f"WIREGUARD_{field.upper()}_INVALID")
    return str(int(text))


def validate_key(value: Any, field: str) -> str:
    """Valida formato externo de clave WireGuard."""
    text = clean(value)
    if not text or text == "********":
        return text
    if not KEY_RE.fullmatch(text):
        fail(f"WIREGUARD_{field.upper()}_INVALID")
    return text


def validate_endpoint(value: Any) -> str:
    """Valida endpoint remoto host:port o [IPv6]:port."""
    text = clean(value)
    if not text:
        return ""
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d{1,5})", text)
    if m:
        try:
            ipaddress.IPv6Address(m.group(1))
        except ValueError:
            fail("WIREGUARD_ENDPOINT_INVALID")
        validate_port(m.group(2), "WIREGUARD_ENDPOINT_PORT_INVALID")
        return text
    m = re.fullmatch(r"([^:\s]+):(\d{1,5})", text)
    if m:
        host = m.group(1)
        host_ok = HOST_RE.fullmatch(host) is not None
        try:
            ipaddress.IPv4Address(host)
            host_ok = True
        except ValueError:
            pass
        if not host_ok:
            fail("WIREGUARD_ENDPOINT_INVALID")
        validate_port(m.group(2), "WIREGUARD_ENDPOINT_PORT_INVALID")
        return text
    fail("WIREGUARD_ENDPOINT_INVALID")


def validate_public_endpoint(value: Any) -> str:
    """Valida endpoint público sin exigir puerto."""
    text = clean(value)
    if not text:
        return ""
    host = text.rsplit(":", 1)[0] if ":" in text and not text.startswith("[") else text
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return text
    except ValueError:
        pass
    if not HOST_RE.fullmatch(host):
        fail("WIREGUARD_PUBLIC_ENDPOINT_INVALID")
    return text


def enabled(rule: dict[str, Any]) -> bool:
    """Indica si una entrada está activa."""
    return clean(rule.get("enabled")) == "true"


def normalize_bool(value: Any) -> str:
    """Normaliza enabled true/false."""
    text = clean(value if value is not None else "false").lower()
    if text not in {"true", "false"}:
        fail("WIREGUARD_BOOL_INVALID")
    return text


def require_fields(rule: dict[str, Any], fields: list[str]) -> None:
    """Exige campos obligatorios cuando la entrada está activa."""
    for field in fields:
        if not clean(rule.get(field)):
            fail("WIREGUARD_REQUIRED_FIELD")


def check_no_overlap(left: list[ipaddress._BaseNetwork | str], right: list[ipaddress._BaseNetwork | str], code: str) -> None:
    """Bloquea solapes de red IPv4/IPv6."""
    for a in left:
        for b in right:
            if isinstance(a, ipaddress._BaseNetwork) and isinstance(b, ipaddress._BaseNetwork) and a.version == b.version and a.overlaps(b):
                fail(code)


def check_ip_inside_networks(ip_list: list[ipaddress._BaseNetwork | str], networks: list[ipaddress._BaseNetwork | str], code: str) -> None:
    """Comprueba que una IP/CIDR host quede dentro de alguna red."""
    if len(ip_list) != 1:
        fail("WIREGUARD_SINGLE_IP_REQUIRED")
    item = ip_list[0]
    if not isinstance(item, ipaddress._BaseNetwork):
        fail(code)
    address = item.network_address
    for network in networks:
        if isinstance(network, ipaddress._BaseNetwork) and network.version == item.version and address in network:
            return
    fail(code)


def validate_no_duplicate_interface(config: dict[str, Any], section: str, name: str, iface: str) -> None:
    """Evita interfaces WireGuard duplicadas en servidores/túneles."""
    if not iface:
        return
    for other_section in ("site_to_site", "remote_access"):
        for other_name, entry in config[other_section].items():
            if other_section == section and other_name == name:
                continue
            if clean(entry.get("interface")) == iface:
                fail("WIREGUARD_INTERFACE_DUPLICATE", status.HTTP_409_CONFLICT)


# ES: Resuelve literals/aliases IP a contenido final para validaciones relacionales WireGuard.
# EN: Resolve IP literals/aliases to final content for WireGuard relational validation.
def resolve_ip_literals(alias_data: dict[str, Any], value: Any) -> list[str]:
    resolved: list[str] = []
    for item in ip_mixed_reference_items(value):
        if isinstance(item, str):
            candidate = item.strip()
            try:
                ipaddress.ip_interface(candidate)
            except ValueError:
                pass
            else:
                resolved.append(candidate)
                continue
        section, entry = find_ip_reference(alias_data, item)
        if section and entry:
            resolved.extend(str(literal).strip() for literal in resolve_ip_deep_content(alias_data, section, entry))
    return resolved


# ES: Resuelve un puerto literal o alias_service simple a su puerto final.
# EN: Resolve one literal port or simple alias_service to its final port.
def resolve_single_port(alias_data: dict[str, Any], value: Any) -> str:
    items = service_mixed_reference_items(value)
    if len(items) != 1:
        return ""
    item = items[0]
    if isinstance(item, str) and item.strip().isdigit():
        return str(int(item.strip()))
    section, entry = find_service_reference(alias_data, item)
    if not section or not entry:
        return ""
    resolved = resolve_service_deep_content(alias_data, section, entry)
    return str(resolved[0]).strip() if len(resolved) == 1 else ""


def validate_no_duplicate_port(config: dict[str, Any], section: str, name: str, port: str) -> None:
    """Evita puertos de escucha duplicados."""
    if not port:
        return
    alias_services = repository.read_alias_services()
    for other_section in ("site_to_site", "remote_access"):
        for other_name, entry in config[other_section].items():
            if other_section == section and other_name == name:
                continue
            other_port = resolve_single_port(alias_services, entry.get("listen_port", ""))
            if other_port == port:
                fail("WIREGUARD_LISTEN_PORT_DUPLICATE", status.HTTP_409_CONFLICT)


def validate_unique_client_values(config: dict[str, Any], name: str, rule: dict[str, Any]) -> None:
    """Evita IPs y claves públicas duplicadas entre clientes remotos."""
    for other_name, entry in config["remote_clients"].items():
        if other_name == name:
            continue
        if clean(rule.get("client_vpn_ip")) and clean(entry.get("client_vpn_ip")) == clean(rule.get("client_vpn_ip")):
            fail("WIREGUARD_CLIENT_IP_DUPLICATE", status.HTTP_409_CONFLICT)
        if clean(rule.get("client_public_key")) and clean(entry.get("client_public_key")) == clean(rule.get("client_public_key")):
            fail("WIREGUARD_CLIENT_PUBLIC_KEY_DUPLICATE", status.HTTP_409_CONFLICT)


def generate_keypair() -> dict[str, str]:
    """Genera un par de claves WireGuard usando wg."""
    private = subprocess.run(["wg", "genkey"], text=True, capture_output=True, timeout=10)
    if private.returncode != 0 or not private.stdout.strip():
        fail("WIREGUARD_KEY_GENERATION_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    public = public_key_from_private(private.stdout.strip())
    return {"private": private.stdout.strip(), "public": public}


def public_key_from_private(private_key: str) -> str:
    """Deriva la clave pública con wg pubkey."""
    proc = subprocess.run(["wg", "pubkey"], input=private_key, text=True, capture_output=True, timeout=10)
    if proc.returncode != 0 or not proc.stdout.strip():
        fail("WIREGUARD_PUBLIC_KEY_DERIVATION_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR)
    return proc.stdout.strip()


def normalize_rule(section: str, raw_rule: dict[str, Any], config: dict[str, Any], name: str, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Valida y normaliza una entrada WireGuard."""
    if not isinstance(raw_rule, dict):
        fail("WIREGUARD_RULE_INVALID")
    rule = {key: clean(value) if isinstance(value, str) else value for key, value in raw_rule.items() if key != "name"}
    existing = existing or {}
    for field in list(rule.keys()):
        if field not in ALLOWED_FIELDS[section] - {"name"}:
            fail("WIREGUARD_UNKNOWN_FIELD")
        if isinstance(rule[field], str) and len(rule[field]) > 512:
            fail("WIREGUARD_FIELD_TOO_LONG")
    normalized = dict(rule)
    normalized["enabled"] = normalize_bool(normalized.get("enabled", existing.get("enabled", "false")))
    for secret in SECRET_FIELDS:
        if normalized.get(secret) == "********" and clean(existing.get(secret)):
            normalized[secret] = existing[secret]
    for field in KEY_FIELDS:
        if field in normalized:
            normalized[field] = validate_key(normalized[field], field)
    if "keepalive" in normalized:
        normalized["keepalive"] = validate_int_range(normalized["keepalive"], "keepalive", 0, 65535)
    if "mtu" in normalized:
        normalized["mtu"] = validate_int_range(normalized["mtu"], "mtu", 576, 9000)
    if "listen_port" in normalized and section == "remote_clients":
        normalized["listen_port"] = validate_port(normalized["listen_port"])
    if "dns" in normalized and section != "remote_access":
        validate_csv_ips(normalized["dns"], "WIREGUARD_DNS_INVALID")
    if "remote_endpoint" in normalized:
        single_ip_port_check(normalized["remote_endpoint"])
    if "public_endpoint" in normalized and section != "remote_access":
        normalized["public_endpoint"] = validate_public_endpoint(normalized["public_endpoint"])
    if section == "site_to_site":
        validated = validate_site_to_site(normalized, config, name)
    elif section == "remote_access":
        validated = validate_remote_access(normalized, config, name)
    else:
        validated = validate_remote_client(normalized, config, name)
    return alias_fields_to_storage(section, validated)


def validate_site_to_site(rule: dict[str, Any], config: dict[str, Any], name: str) -> dict[str, Any]:
    """Valida túnel WireGuard sede-a-sede."""
    if enabled(rule):
        require_fields(rule, ["interface", "local_tunnel_ip", "remote_tunnel_ip", "local_networks", "remote_networks", "listen_port", "remote_endpoint", "private_key", "remote_public_key"])
    iface = clean(rule.get("interface"))
    if iface and not IFACE_RE.fullmatch(iface):
        fail("WIREGUARD_INTERFACE_INVALID")
    validate_no_duplicate_interface(config, "site_to_site", name, iface)

    alias_ip = repository.read_alias_ip()
    alias_services = repository.read_alias_services()
    if ip_mixed_reference_items(rule.get("local_tunnel_ip", "")):
        single_net_check(alias_ip, rule["local_tunnel_ip"])
    if ip_mixed_reference_items(rule.get("remote_tunnel_ip", "")):
        single_net_check(alias_ip, rule["remote_tunnel_ip"])
    if service_mixed_reference_items(rule.get("listen_port", "")):
        single_port_check(alias_services, rule["listen_port"])
    for field in ("local_networks", "remote_networks"):
        if ip_mixed_reference_items(rule.get(field, "")):
            validate_mixed_ip_references(alias_ip, rule[field], allow_groups=True, allow_multiple=True)

    listen_port = resolve_single_port(alias_services, rule.get("listen_port", ""))
    validate_no_duplicate_port(config, "site_to_site", name, listen_port)
    local_tunnel_literals = resolve_ip_literals(alias_ip, rule.get("local_tunnel_ip", ""))
    remote_tunnel_literals = resolve_ip_literals(alias_ip, rule.get("remote_tunnel_ip", ""))
    local_tunnel = [ipaddress.ip_interface(value) for value in local_tunnel_literals]
    remote_tunnel = [ipaddress.ip_interface(value) for value in remote_tunnel_literals]
    if local_tunnel and remote_tunnel:
        left, right = local_tunnel[0], remote_tunnel[0]
        if left.version != right.version:
            fail("WIREGUARD_TUNNEL_FAMILY_MISMATCH")
        if left.network != right.network:
            fail("WIREGUARD_TUNNEL_NETWORK_MISMATCH")
        if left.ip == right.ip:
            fail("WIREGUARD_TUNNEL_ENDPOINT_DUPLICATE")

    local_network_literals = resolve_ip_literals(alias_ip, rule.get("local_networks", ""))
    remote_network_literals = resolve_ip_literals(alias_ip, rule.get("remote_networks", ""))
    local_nets = [ipaddress.ip_network(value, strict=False) for value in local_network_literals]
    remote_nets = [ipaddress.ip_network(value, strict=False) for value in remote_network_literals]
    if local_nets and remote_nets:
        check_no_overlap(local_nets, remote_nets, "WIREGUARD_NETWORKS_OVERLAP")
    return rule


def validate_remote_access(rule: dict[str, Any], config: dict[str, Any], name: str) -> dict[str, Any]:
    """Valida servidor WireGuard de acceso remoto con referencias Alias mixtas."""
    if enabled(rule):
        require_fields(rule, ["interface", "server_vpn_ip", "vpn_network", "listen_port", "internal_networks", "private_key"])
    iface = clean(rule.get("interface"))
    if iface and not IFACE_RE.fullmatch(iface):
        fail("WIREGUARD_INTERFACE_INVALID")
    validate_no_duplicate_interface(config, "remote_access", name, iface)

    alias_ip = repository.read_alias_ip()
    alias_services = repository.read_alias_services()
    if ip_mixed_reference_items(rule.get("server_vpn_ip", "")):
        single_net_check(alias_ip, rule["server_vpn_ip"])
    for field in ("vpn_network", "internal_networks"):
        if ip_mixed_reference_items(rule.get(field, "")):
            validate_mixed_ip_references(alias_ip, rule[field], allow_groups=True, allow_multiple=True)
    if service_mixed_reference_items(rule.get("listen_port", "")):
        single_port_check(alias_services, rule["listen_port"])

    listen_port = resolve_single_port(alias_services, rule.get("listen_port", ""))
    validate_no_duplicate_port(config, "remote_access", name, listen_port)

    dns_items = ip_mixed_reference_items(rule.get("dns", ""))
    for item in dns_items:
        single_host_check(alias_ip, [item])

    endpoint_items = ip_mixed_reference_items(rule.get("public_endpoint", ""))
    if endpoint_items:
        single_domain_or_ip_check(alias_ip, rule.get("public_endpoint", ""))
    if len(endpoint_items) > 1:
        fail("WIREGUARD_PUBLIC_ENDPOINT_INVALID")
    if endpoint_items:
        endpoint_item = endpoint_items[0]
        ref_section, ref_entry = find_ip_reference(alias_ip, endpoint_item)
        if isinstance(endpoint_item, dict) or ref_section is not None:
            single_host_check(alias_ip, [endpoint_item])
        elif isinstance(endpoint_item, str):
            try:
                ipaddress.ip_interface(endpoint_item) if "/" in endpoint_item else ipaddress.ip_address(endpoint_item)
            except ValueError:
                validate_public_endpoint(endpoint_item)
            else:
                single_host_check(alias_ip, [endpoint_item])
        else:
            fail("WIREGUARD_PUBLIC_ENDPOINT_INVALID")

    server_literals = resolve_ip_literals(alias_ip, rule.get("server_vpn_ip", ""))
    vpn_literals = resolve_ip_literals(alias_ip, rule.get("vpn_network", ""))
    internal_literals = resolve_ip_literals(alias_ip, rule.get("internal_networks", ""))
    server_ips = [ipaddress.ip_interface(value) for value in server_literals]
    vpn_nets = [ipaddress.ip_network(value, strict=False) for value in vpn_literals]
    internal_nets = [ipaddress.ip_network(value, strict=False) for value in internal_literals]
    if len(server_ips) > 1:
        fail("WIREGUARD_SINGLE_SERVER_IP_REQUIRED")
    if server_ips and vpn_nets:
        server_ip = server_ips[0]
        if not any(server_ip.version == network.version and server_ip.ip in network for network in vpn_nets):
            fail("WIREGUARD_SERVER_IP_OUTSIDE_VPN")
    if vpn_nets and internal_nets:
        check_no_overlap(vpn_nets, internal_nets, "WIREGUARD_NETWORKS_OVERLAP")
    return rule


def validate_remote_client(rule: dict[str, Any], config: dict[str, Any], name: str) -> dict[str, Any]:
    """Valida cliente remoto WireGuard."""
    if clean(rule.get("client_private_key")) == "" or clean(rule.get("client_public_key")) == "":
        pair = generate_keypair()
        if clean(rule.get("client_private_key")) == "":
            rule["client_private_key"] = pair["private"]
        if clean(rule.get("client_public_key")) == "":
            rule["client_public_key"] = pair["public"]
    for field in ("client_private_key", "client_public_key"):
        rule[field] = validate_key(rule.get(field), field)
    if enabled(rule):
        require_fields(rule, ["vpn", "client_vpn_ip", "client_private_key", "client_public_key", "allowed_ips"])
    vpn = clean(rule.get("vpn"))
    if vpn and not NAME_RE.fullmatch(vpn):
        fail("WIREGUARD_VPN_NAME_INVALID")
    if vpn:
        if vpn not in config["remote_access"]:
            fail("WIREGUARD_CLIENT_VPN_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        client_ips = validate_csv_cidrs(rule.get("client_vpn_ip"), "WIREGUARD_CLIENT_VPN_IP_INVALID")
        alias_ip = repository.read_alias_ip()
        vpn_literals = resolve_ip_literals(alias_ip, config["remote_access"][vpn].get("vpn_network", ""))
        vpn_nets = [ipaddress.ip_network(value, strict=False) for value in vpn_literals]
        if client_ips and vpn_nets:
            check_ip_inside_networks(client_ips, vpn_nets, "WIREGUARD_CLIENT_IP_OUTSIDE_VPN")
    validate_csv_cidrs(rule.get("allowed_ips"), "WIREGUARD_ALLOWED_IPS_INVALID", allow_default=False)
    validate_unique_client_values(config, name, rule)
    return rule


def list_section(section: str) -> dict[str, dict[str, Any]]:
    """Lista una sección traduciendo UUIDs Alias a names visibles."""
    data = read_config()
    return {name: mask_entry(alias_fields_to_frontend(section, entry)) for name, entry in data[section].items()}


def get_entry(section: str, name: str, *, masked: bool = True) -> dict[str, Any]:
    """Obtiene todas las entradas WireGuard por su identidad UUID."""
    data = read_config()
    if section == "site_to_site":
        _, entry = find_site_to_site_by_uuid(data, name)
        if entry is None:
            fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    elif section == "remote_access":
        _, entry = find_remote_access_by_uuid(data, name)
        if entry is None:
            fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    elif section == "remote_clients":
        _, entry = find_remote_client_by_uuid(data, name)
        if entry is None:
            fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    else:
        clean_name = validate_name(name)
        if clean_name not in data[section]:
            fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        entry = data[section][clean_name]
    return mask_entry(alias_fields_to_frontend(section, entry)) if masked else dict(entry)


def create_entry(section: str, rule: dict[str, Any]) -> dict[str, Any]:
    """Crea una entrada WireGuard."""
    with repository.config_lock():
        data = read_config()
        name = clean(rule.get("name"))
        if section == "site_to_site":
            name = validate_name(name)
            ensure_unique_site_to_site_name(data, name)
            entry_id = site_to_site_next_id(data)
            uuid = generate_unique_internal_uuid("wgsite", entry_id, site_to_site_existing_uuids(data))
            normalized = normalize_rule(section, rule, data, uuid)
            entry = {"id": entry_id, "UUID": uuid, "name": name, **normalized}
            data[section][uuid] = entry
            repository.write_config(data)
            return {"success": True, "action": "create", "section": section, "id": entry_id, "UUID": uuid, "name": name, "updated": uuid}
        if section == "remote_access":
            name = validate_name(name)
            ensure_unique_remote_access_name(data, name)
            entry_id = remote_access_next_id(data)
            uuid = generate_unique_internal_uuid("wgserv", entry_id, remote_access_existing_uuids(data))
            normalized = normalize_rule(section, rule, data, uuid)
            entry = {"id": entry_id, "UUID": uuid, "name": name, **normalized}
            data[section][uuid] = entry
            repository.write_config(data)
            return {"success": True, "action": "create", "section": section, "id": entry_id, "UUID": uuid, "name": name, "updated": uuid}
        if section == "remote_clients":
            name = validate_name(name)
            ensure_unique_remote_client_name(data, name)
            entry_id = remote_client_next_id(data)
            uuid = generate_unique_internal_uuid("wgclient", entry_id, remote_client_existing_uuids(data))
            normalized = normalize_rule(section, rule, data, uuid)
            entry = {"id": entry_id, "UUID": uuid, "name": name, **normalized}
            data[section][uuid] = entry
            repository.write_config(data)
            return {"success": True, "action": "create", "section": section, "id": entry_id, "UUID": uuid, "name": name, "updated": uuid}
        if name in ("", "Auto"):
            name = make_name(data, section)
        name = validate_name(name)
        if name in data[section]:
            fail("WIREGUARD_ENTRY_ALREADY_EXISTS", status.HTTP_409_CONFLICT)
        normalized = normalize_rule(section, rule, data, name)
        data[section][name] = normalized
        repository.write_config(data)
    return {"success": True, "action": "create", "section": section, "name": name, "updated": name}


def update_entry(section: str, name: str, rule: dict[str, Any]) -> dict[str, Any]:
    """Actualiza entradas WireGuard por UUID."""
    if section == "site_to_site":
        clean_uuid = clean(name)
        with repository.config_lock():
            data = read_config()
            key, existing = find_site_to_site_by_uuid(data, clean_uuid)
            if key is None or existing is None:
                fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            display_name = validate_name(clean(rule.get("name", existing.get("name"))))
            ensure_unique_site_to_site_name(data, display_name, clean_uuid)
            merged = {k: v for k, v in existing.items() if k not in {"id", "UUID", "name"}}
            merged.update({k: v for k, v in rule.items() if k not in {"id", "UUID", "name"}})
            normalized = normalize_rule(section, merged, data, clean_uuid, existing)
            updated = {"id": clean(existing.get("id")), "UUID": clean_uuid, "name": display_name, **normalized}
            if key != clean_uuid:
                data[section].pop(key, None)
            data[section][clean_uuid] = updated
            repository.write_config(data)
        return {"success": True, "action": "update", "section": section, "id": updated["id"], "UUID": clean_uuid, "name": display_name, "updated": clean_uuid}
    if section == "remote_access":
        clean_uuid = clean(name)
        with repository.config_lock():
            data = read_config()
            key, existing = find_remote_access_by_uuid(data, clean_uuid)
            if key is None or existing is None:
                fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            display_name = validate_name(clean(rule.get("name", existing.get("name"))))
            ensure_unique_remote_access_name(data, display_name, clean_uuid)
            merged = {k: v for k, v in existing.items() if k not in {"id", "UUID", "name"}}
            merged.update({k: v for k, v in rule.items() if k not in {"id", "UUID", "name"}})
            normalized = normalize_rule(section, merged, data, clean_uuid, existing)
            updated = {"id": clean(existing.get("id")), "UUID": clean_uuid, "name": display_name, **normalized}
            if key != clean_uuid:
                data[section].pop(key, None)
            data[section][clean_uuid] = updated
            repository.write_config(data)
        return {"success": True, "action": "update", "section": section, "id": updated["id"], "UUID": clean_uuid, "name": display_name, "updated": clean_uuid}
    if section == "remote_clients":
        clean_uuid = clean(name)
        with repository.config_lock():
            data = read_config()
            key, existing = find_remote_client_by_uuid(data, clean_uuid)
            if key is None or existing is None:
                fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            display_name = validate_name(clean(rule.get("name", existing.get("name"))))
            ensure_unique_remote_client_name(data, display_name, clean_uuid)
            for key_field in ("client_private_key", "client_public_key"):
                if key_field in rule and clean(rule.get(key_field)) != clean(existing.get(key_field)):
                    fail("WIREGUARD_CLIENT_KEYS_NOT_EDITABLE")
            merged = {k: v for k, v in existing.items() if k not in {"id", "UUID", "name"}}
            merged.update({k: v for k, v in rule.items() if k not in {"id", "UUID", "name"}})
            normalized = normalize_rule(section, merged, data, clean_uuid, existing)
            updated = {"id": clean(existing.get("id")), "UUID": clean_uuid, "name": display_name, **normalized}
            if key != clean_uuid:
                data[section].pop(key, None)
            data[section][clean_uuid] = updated
            repository.write_config(data)
        return {"success": True, "action": "update", "section": section, "id": updated["id"], "UUID": clean_uuid, "name": display_name, "updated": clean_uuid}
    clean_name = validate_name(name)
    body_name = clean(rule.get("name"))
    if body_name and body_name not in {clean_name, "Auto"}:
        fail("WIREGUARD_NAME_MISMATCH")
    with repository.config_lock():
        data = read_config()
        if clean_name not in data[section]:
            fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        merged = dict(data[section][clean_name])
        merged.update({key: value for key, value in rule.items() if key != "name"})
        normalized = normalize_rule(section, merged, data, clean_name, data[section][clean_name])
        data[section][clean_name] = normalized
        repository.write_config(data)
    return {"success": True, "action": "update", "section": section, "name": clean_name, "updated": clean_name}


def delete_entry(section: str, name: str) -> dict[str, Any]:
    """Borra entradas WireGuard por UUID."""
    if section == "site_to_site":
        clean_uuid = clean(name)
        with repository.config_lock():
            data = read_config()
            key, existing = find_site_to_site_by_uuid(data, clean_uuid)
            if key is None or existing is None:
                fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            data[section].pop(key, None)
            repository.write_config(data)
        return {"success": True, "action": "delete", "section": section, "id": clean(existing.get("id")), "UUID": clean_uuid, "name": clean(existing.get("name")), "deleted": clean_uuid}
    if section == "remote_access":
        clean_uuid = clean(name)
        with repository.config_lock():
            data = read_config()
            key, existing = find_remote_access_by_uuid(data, clean_uuid)
            if key is None or existing is None:
                fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            for client in data["remote_clients"].values():
                if clean(client.get("vpn")) == clean_uuid:
                    fail("WIREGUARD_REMOTE_ACCESS_HAS_CLIENTS", status.HTTP_409_CONFLICT)
            data[section].pop(key, None)
            repository.write_config(data)
        return {"success": True, "action": "delete", "section": section, "id": clean(existing.get("id")), "UUID": clean_uuid, "name": clean(existing.get("name")), "deleted": clean_uuid}
    if section == "remote_clients":
        clean_uuid = clean(name)
        with repository.config_lock():
            data = read_config()
            key, existing = find_remote_client_by_uuid(data, clean_uuid)
            if key is None or existing is None:
                fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            data[section].pop(key, None)
            repository.write_config(data)
        return {"success": True, "action": "delete", "section": section, "id": clean(existing.get("id")), "UUID": clean_uuid, "name": clean(existing.get("name")), "deleted": clean_uuid}
    clean_name = validate_name(name)
    with repository.config_lock():
        data = read_config()
        if clean_name not in data[section]:
            fail("WIREGUARD_ENTRY_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        if section == "remote_access":
            for client in data["remote_clients"].values():
                if clean(client.get("vpn")) == clean_name:
                    fail("WIREGUARD_REMOTE_ACCESS_HAS_CLIENTS", status.HTTP_409_CONFLICT)
        del data[section][clean_name]
        repository.write_config(data)
    return {"success": True, "action": "delete", "section": section, "name": clean_name, "deleted": clean_name}


def endpoint_host(server: dict[str, Any], fallback_host: str = "") -> str:
    """Resuelve host externo literal o Alias para clientes WireGuard."""
    configured_value = server.get("public_endpoint", "")
    configured_items = ip_mixed_reference_items(configured_value)
    configured = ""
    if configured_items:
        item = configured_items[0]
        alias_ip = repository.read_alias_ip()
        ref_section, _ = find_ip_reference(alias_ip, item)
        if isinstance(item, dict) or ref_section is not None:
            resolved = resolve_ip_literals(alias_ip, [item])
            if resolved:
                candidate = resolved[0]
                try:
                    configured = str(ipaddress.ip_interface(candidate).ip) if "/" in candidate else str(ipaddress.ip_address(candidate))
                except ValueError:
                    configured = candidate
        else:
            configured = clean(item)
    host = configured or fallback_host
    if host.startswith("[") and "]" in host:
        return host.split("]", 1)[0].strip("[]")
    if ":" in host:
        return host.rsplit(":", 1)[0]
    return host


def build_client_config(name: str, fallback_host: str = "") -> str:
    """Construye el archivo .conf de un cliente remoto identificado por UUID."""
    client = get_entry("remote_clients", name, masked=False)
    display_name = clean(client.get("name")) or name
    data = read_config()
    vpn = clean(client.get("vpn"))
    if vpn not in data["remote_access"]:
        fail("WIREGUARD_CLIENT_EXPORT_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    server = data["remote_access"][vpn]
    client_private = clean(client.get("client_private_key"))
    server_private = clean(server.get("private_key"))
    alias_services = repository.read_alias_services()
    listen_port = resolve_single_port(alias_services, server.get("listen_port", ""))
    host = endpoint_host(server, fallback_host)
    if not client_private or not server_private or not listen_port or not host:
        fail("WIREGUARD_CLIENT_EXPORT_INCOMPLETE")
    server_public = public_key_from_private(server_private)
    lines = [
        "# Cliente WireGuard generado por PraesidiumFirewall.",
        "# WireGuard client generated by PraesidiumFirewall.",
        f"# Cliente: {display_name}; VPN: {vpn}",
        "[Interface]",
        f"PrivateKey = {client_private}",
        f"Address = {clean(client.get('client_vpn_ip'))}",
    ]
    alias_ip = repository.read_alias_ip()
    dns_values = resolve_ip_literals(alias_ip, server.get("dns", ""))
    dns = ", ".join(str(ipaddress.ip_interface(value).ip) if "/" in value else value for value in dns_values)
    if dns:
        lines.append(f"DNS = {dns}")
    lines.extend(["", "[Peer]", f"PublicKey = {server_public}", f"Endpoint = {host}:{listen_port}"])
    allowed_values = resolve_ip_literals(alias_ip, server.get("internal_networks", ""))
    allowed = ", ".join(allowed_values) or "0.0.0.0/0"
    lines.append(f"AllowedIPs = {allowed}")
    keepalive = clean(client.get("keepalive"))
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


def download_filename(name: str, extension: str) -> str:
    """Normaliza nombres de archivo descargable."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    return f"{safe or 'wireguard-client'}.{extension}"


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Construye un chunk PNG con CRC."""
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)


def _matrix_to_png(matrix: list[list[bool]], scale: int = 8) -> bytes:
    """Convierte una matriz QR booleana a PNG grayscale sin PIL/qrencode."""
    width = len(matrix[0]) * scale
    height = len(matrix) * scale
    rows: list[bytes] = []
    for qr_row in matrix:
        expanded = bytearray()
        for cell in qr_row:
            expanded.extend((0 if cell else 255 for _ in range(scale)))
        row = b"\x00" + bytes(expanded)
        for _ in range(scale):
            rows.append(row)
    raw = b"".join(rows)
    png = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
    png += _png_chunk(b"IDAT", zlib.compress(raw, level=9))
    png += _png_chunk(b"IEND", b"")
    return png


def generate_qr_png(config_text: str) -> bytes:
    """Genera QR PNG usando qrencode o fallback Python vendorizado."""
    qrencode = subprocess.run(["bash", "-lc", "command -v qrencode"], text=True, capture_output=True, timeout=5)
    if qrencode.returncode == 0 and qrencode.stdout.strip():
        proc = subprocess.run(["qrencode", "-t", "PNG", "-o", "-"], input=config_text.encode(), capture_output=True, timeout=20)
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout
    sys.path.insert(0, str(repository.scripts_dir()))
    try:
        import qrcode  # type: ignore
        qr = qrcode.QRCode(border=4)
        qr.add_data(config_text)
        qr.make(fit=True)
        return _matrix_to_png(qr.get_matrix())
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"status": "error", "error_code": "WIREGUARD_QR_GENERATION_FAILED"}) from exc


def build_bundle(name: str, fallback_host: str = "") -> bytes:
    """Construye ZIP con .conf y QR PNG para un UUID de cliente."""
    client = get_entry("remote_clients", name, masked=False)
    display_name = clean(client.get("name")) or name
    config_text = build_client_config(name, fallback_host)
    qr = generate_qr_png(config_text)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(download_filename(display_name, "conf"), config_text)
        archive.writestr(download_filename(display_name, "png"), qr)
    return buffer.getvalue()
