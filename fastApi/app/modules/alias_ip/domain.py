"""
Reglas de dominio de Alias IP.
Alias IP domain rules.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid

SIMPLE_SECTION = "alias_address"
GROUP_SECTION = "alias_addr_group"
SECTIONS = (SIMPLE_SECTION, GROUP_SECTION)
UUID_PREFIXES = {SIMPLE_SECTION: "aliasad", GROUP_SECTION: "aliagroup"}
VALUE_KIND = "ip"


# Devuelve el prefijo UUID oficial para una sección alias.
# Returns the official UUID prefix for an alias section.
def uuid_prefix_for_section(section: str) -> str:
    return UUID_PREFIXES.get(section, "alias")


# Detecta la sección alias a partir del prefijo del UUID.
# Detects the alias section from the UUID prefix.
def section_from_uuid(uuid: str) -> str | None:
    prefix = str(uuid).split("-", 1)[0]
    for section, section_prefix in UUID_PREFIXES.items():
        if prefix == section_prefix:
            return section
    return None


# Normaliza content aceptando listas/cadenas y eliminando duplicados vacíos.
# Normalizes content from lists/strings and removes empty duplicates.
def normalize_content(content: Any) -> list[str]:
    raw_values: list[Any] = []
    if content is None:
        return []
    if isinstance(content, str):
        raw_values = content.split(",")
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, str) and "," in item:
                raw_values.extend(item.split(","))
            else:
                raw_values.append(item)
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_ALIAS_CONTENT")
    out: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        clean = str(value).strip()
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


# Devuelve las entradas de una sección soportando mapa UUID y lista legacy.
# Returns entries for one section supporting UUID maps and legacy lists.
def section_entries(data: dict[str, Any], section: str) -> list[dict[str, Any]]:
    items = data.get(section, {})
    if isinstance(items, dict):
        values = items.values()
    elif isinstance(items, list):
        values = items
    else:
        values = []
    return [item for item in values if isinstance(item, dict)]


# Busca una entrada de sección por UUID.
# Finds a section entry by UUID.
def find_entry_by_uuid(data: dict[str, Any], section: str, uuid: str) -> dict[str, Any] | None:
    for entry in section_entries(data, section):
        if str(entry.get("UUID", "")) == uuid:
            return entry
    return None


# Busca una entrada de sección por nombre visible.
# Finds a section entry by visible name.
def find_entry_by_name(data: dict[str, Any], section: str, name: str) -> dict[str, Any] | None:
    for entry in section_entries(data, section):
        if str(entry.get("name", "")) == name:
            return entry
    return None


# Busca una referencia por UUID o nombre dentro de la familia actual.
# Finds a reference by UUID or name inside the current family.
def find_entry_any(data: dict[str, Any], value: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    section = section_from_uuid(value)
    if section is not None:
        if section not in SECTIONS:
            return None, None
        entry = find_entry_by_uuid(data, section, value)
        return (section, entry) if entry else (section, None)
    for candidate_section in SECTIONS:
        entry = find_entry_by_name(data, candidate_section, value)
        if entry:
            return candidate_section, entry
    return None, None


# Devuelve UUIDs existentes dentro de la familia actual para evitar colisiones.
# Returns existing UUIDs inside the current family to avoid collisions.
def existing_uuids(data: dict[str, Any]) -> set[str]:
    return {str(entry.get("UUID")) for section in SECTIONS for entry in section_entries(data, section) if entry.get("UUID")}


# Calcula el menor id positivo libre para la sección.
# Calculates the first free positive id for the section.
def next_id(data: dict[str, Any], section: str) -> str:
    used: set[int] = set()
    for entry in section_entries(data, section):
        try:
            value = int(str(entry.get("id", "")))
        except ValueError:
            continue
        if value > 0:
            used.add(value)
    candidate = 1
    while candidate in used:
        candidate += 1
    return str(candidate)


# Genera un UUID Praesidium único para la sección.
# Generates a unique Praesidium UUID for the section.
def generate_uuid(data: dict[str, Any], section: str, entry_id: str) -> str:
    prefix = uuid_prefix_for_section(section)
    return generate_unique_internal_uuid(prefix, entry_id, existing_uuids(data))


# Ordena la entrada para colocar UUID justo después de id.
# Orders the entry so UUID appears right after id.
def order_entry_uuid(entry: dict[str, Any], uuid: str) -> dict[str, Any]:
    ordered: dict[str, Any] = {}
    inserted = False
    for key, value in entry.items():
        if key == "UUID":
            continue
        ordered[key] = value
        if key == "id":
            ordered["UUID"] = uuid
            inserted = True
    if not inserted:
        ordered["UUID"] = uuid
    return ordered


# Normaliza el JSON completo de la familia a mapas UUID.
# Normalizes the full family JSON into UUID maps.
def normalize_store(data: dict[str, Any]) -> dict[str, Any]:
    normalized = {SIMPLE_SECTION: {}, GROUP_SECTION: {}}
    for section in SECTIONS:
        section_map: dict[str, dict[str, Any]] = {}
        temp = dict(normalized)
        temp[section] = section_map
        for entry in section_entries(data, section):
            if "id" not in entry:
                continue
            uuid = str(entry.get("UUID") or "")
            if not uuid:
                uuid = generate_uuid(temp, section, str(entry.get("id", "")))
            clean = dict(entry)
            clean["content"] = normalize_content(clean.get("content", []))
            clean = order_entry_uuid(clean, uuid)
            section_map[uuid] = clean
        normalized[section] = section_map
    return normalized


# Añade un valor preservando orden y evitando duplicados.
# Appends one value preserving order and avoiding duplicates.
def _append_unique(values: list[str], seen: set[str], value: str) -> None:
    if value not in seen:
        seen.add(value)
        values.append(value)


# Convierte storage interno a formato visible para API/WebGUI.
# Converts internal storage into visible API/WebGUI format.
def entry_to_frontend(data: dict[str, Any], section: str, entry: dict[str, Any]) -> dict[str, Any]:
    public = order_entry_uuid(dict(entry), str(entry.get("UUID", "")))
    content = normalize_content(public.get("content", []))
    if section == GROUP_SECTION:
        visible: list[str] = []
        for value in content:
            _, target = find_entry_any(data, value)
            visible.append(str(target.get("name")) if target else value)
        public["content"] = visible
    else:
        public["content"] = content
    public["id"] = str(public.get("id", ""))
    public["UUID"] = str(public.get("UUID", ""))
    public["name"] = str(public.get("name", ""))
    return public


# Convierte entrada visible a storage interno UUID/literal.
# Converts a visible entry into internal UUID/literal storage.
def entry_to_storage(data: dict[str, Any], section: str, entry: dict[str, Any]) -> dict[str, Any]:
    stored = dict(entry)
    content = normalize_content(stored.get("content", []))
    if section == GROUP_SECTION:
        internal: list[str] = []
        seen: set[str] = set()
        for value in content:
            _, target = find_entry_any(data, value)
            clean = str(target.get("UUID")) if target else value
            _append_unique(internal, seen, clean)
        stored["content"] = internal
    else:
        stored["content"] = content
    return stored


# Valida que la sección pertenezca a esta familia alias.
# Validates that the section belongs to this alias family.
def ensure_section(section: str) -> None:
    if section not in SECTIONS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_SECTION_NOT_FOUND")


# Limpia y valida el nombre visible del alias.
# Cleans and validates the alias visible name.
def clean_name(name: str) -> str:
    clean = str(name).strip()
    if not clean:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_NAME_REQUIRED")
    if len(clean) >= 30:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_NAME_TOO_LONG")
    return clean


# Garantiza que el nombre no se repita dentro de la familia.
# Ensures the name is not duplicated within the family.
def ensure_unique_name(data: dict[str, Any], name: str, ignore_uuid: str = "") -> None:
    for section in SECTIONS:
        for entry in section_entries(data, section):
            if ignore_uuid and str(entry.get("UUID", "")) == ignore_uuid:
                continue
            if str(entry.get("name", "")).strip() == name:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ALIAS_NAME_ALREADY_EXISTS")


# Valida el valor final literal de la familia.
# Validates the final literal value for the family.
def validate_final_value(value: str) -> None:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_IP_OR_CIDR") from exc


def mixed_reference_items(value: Any) -> list[Any]:
    if value is None or value == "" or value == []:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            if isinstance(item, str) and "," in item:
                out.extend(part.strip() for part in item.split(",") if part.strip())
            elif item not in (None, ""):
                out.append(item)
        return out
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [value]


def find_entry_reference(data: dict[str, Any], reference: Any) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    uuid = ""
    name = ""
    if isinstance(reference, dict):
        uuid = str(reference.get("UUID", "")).strip()
        name = str(reference.get("name", "")).strip()
    elif isinstance(reference, str):
        uuid = reference.strip()
        name = reference.strip()
    else:
        return None, None
    if not uuid and not name:
        return None, None
    if uuid:
        section = section_from_uuid(uuid)
        if section in SECTIONS:
            entry = find_entry_by_uuid(data, section, uuid)
            if entry:
                if isinstance(reference, dict) and name and str(entry.get("name", "")).strip() != name:
                    return None, None
                return section, entry
            return section, None
    if name:
        for candidate_section in SECTIONS:
            entry = find_entry_by_name(data, candidate_section, name)
            if entry:
                return candidate_section, entry
    return None, None


def validate_mixed_ip_item(data: dict[str, Any], item: Any, *, allow_groups: bool = True, stack: tuple[str, ...] = (), depth: int = 0, max_depth: int = 64) -> None:
    if depth > max_depth:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ALIAS_RECURSION_LIMIT_EXCEEDED")
    if isinstance(item, str):
        text = item.strip()
        if text == "":
            return
        try:
            validate_final_value(text)
            return
        except HTTPException:
            pass
    ref_section, ref_entry = find_entry_reference(data, item)
    if ref_section is not None and ref_entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_REFERENCE_NOT_FOUND")
    if ref_section is None or ref_entry is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_IP_OR_ALIAS")
    if ref_section == GROUP_SECTION and not allow_groups:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_GROUP_NOT_ALLOWED")
    uuid = str(ref_entry.get("UUID", ""))
    if uuid and uuid in stack:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ALIAS_RECURSION_DETECTED")
    next_stack = stack + ((uuid,) if uuid else ())
    for child in mixed_reference_items(ref_entry.get("content", [])):
        validate_mixed_ip_item(data, child, allow_groups=allow_groups, stack=next_stack, depth=depth + 1, max_depth=max_depth)


def validate_mixed_ip_references(data: dict[str, Any], value: Any, *, allow_groups: bool = True, allow_multiple: bool = True, allow_default: bool = False) -> None:
    items = mixed_reference_items(value)
    if not items:
        return
    if not allow_multiple and len(items) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_IP_CIDR_OR_ALIAS_ALLOWED")
    for item in items:
        if allow_default and isinstance(item, str) and item.strip() == "default":
            continue
        validate_mixed_ip_item(data, item, allow_groups=allow_groups)


# Comprueba un único dominio literal, IP host o alias simple que resuelva a una IP host.
# Checks one literal domain, host IP, or simple alias resolving to one host IP.
def single_domain_or_ip_check(data: dict[str, Any], value: Any) -> None:
    items = mixed_reference_items(value)
    if len(items) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_DOMAIN_OR_IP_ALLOWED")

    item = items[0]
    ref_section, ref_entry = find_entry_reference(data, item)
    if ref_section is not None:
        if ref_entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_REFERENCE_NOT_FOUND")
        if ref_section != SIMPLE_SECTION:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_GROUP_NOT_ALLOWED")
        resolved = resolve_deep_content(data, ref_section, ref_entry)
        if len(resolved) != 1:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_DOMAIN_OR_IP_ALLOWED")
        candidate = str(resolved[0]).strip()
        try:
            address = ipaddress.ip_interface(candidate) if "/" in candidate else ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_DOMAIN_OR_IP") from exc
        prefixlen = address.network.prefixlen if isinstance(address, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)) else address.max_prefixlen
        if prefixlen != address.max_prefixlen:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_HOST_REQUIRED")
        return

    if not isinstance(item, str):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_DOMAIN_OR_IP")
    candidate = item.strip()
    try:
        address = ipaddress.ip_interface(candidate) if "/" in candidate else ipaddress.ip_address(candidate)
    except ValueError:
        if len(candidate) > 253 or "." not in candidate:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_DOMAIN_OR_IP")
        labels = candidate.split(".")
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) is None
            for label in labels
        ):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_DOMAIN_OR_IP")
        return
    prefixlen = address.network.prefixlen if isinstance(address, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)) else address.max_prefixlen
    if prefixlen != address.max_prefixlen:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_HOST_REQUIRED")


# Comprueba que un literal o alias simple resuelva a un único host IPv4/IPv6.
# Checks that a literal or simple alias resolves to one IPv4/IPv6 host.
def single_host_check(data: dict[str, Any], value: Any) -> None:
    items = mixed_reference_items(value)
    if len(items) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_HOST_OR_ALIAS_ALLOWED")

    item = items[0]
    host_value = ""
    if isinstance(item, str):
        candidate = item.strip()
        try:
            address = ipaddress.ip_interface(candidate) if "/" in candidate else ipaddress.ip_address(candidate)
            prefixlen = address.network.prefixlen if isinstance(address, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)) else address.max_prefixlen
            max_prefixlen = address.max_prefixlen
            if prefixlen != max_prefixlen:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_HOST_REQUIRED")
            return
        except ValueError:
            pass

    ref_section, ref_entry = find_entry_reference(data, item)
    if ref_section is not None and ref_entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_REFERENCE_NOT_FOUND")
    if ref_section is None or ref_entry is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_IP_OR_ALIAS")
    if ref_section != SIMPLE_SECTION:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_GROUP_NOT_ALLOWED")

    resolved = resolve_deep_content(data, ref_section, ref_entry)
    if len(resolved) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_HOST_OR_ALIAS_ALLOWED")
    host_value = str(resolved[0]).strip()
    try:
        address = ipaddress.ip_interface(host_value) if "/" in host_value else ipaddress.ip_address(host_value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_IP_OR_ALIAS") from exc
    prefixlen = address.network.prefixlen if isinstance(address, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)) else address.max_prefixlen
    if prefixlen != address.max_prefixlen:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_HOST_REQUIRED")


# Comprueba que un literal o alias simple resuelva a una única IP con prefijo de red no host.
# Checks that a literal or simple alias resolves to one IP with a non-host network prefix.
def single_net_check(data: dict[str, Any], value: Any) -> None:
    items = mixed_reference_items(value)
    if len(items) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_NET_OR_ALIAS_ALLOWED")

    item = items[0]
    if isinstance(item, str):
        candidate = item.strip()
        if "/" in candidate:
            try:
                network_value = ipaddress.ip_interface(candidate)
            except ValueError:
                pass
            else:
                if network_value.network.prefixlen < network_value.max_prefixlen:
                    return
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_NET_REQUIRED")
        else:
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                pass
            else:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_NET_REQUIRED")

    ref_section, ref_entry = find_entry_reference(data, item)
    if ref_section is not None and ref_entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_REFERENCE_NOT_FOUND")
    if ref_section is None or ref_entry is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_IP_OR_ALIAS")
    if ref_section != SIMPLE_SECTION:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_GROUP_NOT_ALLOWED")

    resolved = resolve_deep_content(data, ref_section, ref_entry)
    if len(resolved) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_NET_OR_ALIAS_ALLOWED")
    network_text = str(resolved[0]).strip()
    if "/" not in network_text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_NET_REQUIRED")
    try:
        network_value = ipaddress.ip_interface(network_text)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_IP_OR_ALIAS") from exc
    if network_value.network.prefixlen >= network_value.max_prefixlen:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_NET_REQUIRED")


# Comprueba un único endpoint literal IP:puerto; no acepta aliases, CIDR ni hostnames.
# Checks one literal IP:port endpoint; aliases, CIDR, and hostnames are not accepted.
def single_ip_port_check(value: Any) -> None:
    if not isinstance(value, str):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_IP_PORT_REQUIRED")
    endpoint = value.strip()
    if not endpoint or "/" in endpoint or "," in endpoint:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_IP_PORT_REQUIRED")

    ip_text = ""
    port_text = ""
    expected_version = 4
    if endpoint.startswith("["):
        closing = endpoint.find("]:")
        if closing <= 1 or endpoint.find("]:", closing + 2) != -1:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_IP_PORT_REQUIRED")
        ip_text = endpoint[1:closing]
        port_text = endpoint[closing + 2:]
        expected_version = 6
    else:
        if endpoint.count(":") != 1:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_IP_PORT_REQUIRED")
        ip_text, port_text = endpoint.rsplit(":", 1)

    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_IP_PORT_REQUIRED") from exc
    if address.version != expected_version:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_IP_PORT_REQUIRED")
    if not port_text.isdigit() or int(port_text) < 1 or int(port_text) > 65535:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_IP_PORT_REQUIRED")


# Valida content según si es alias simple o grupo.
# Validates content depending on simple alias or group.
def validate_content(data: dict[str, Any], section: str, content: list[str]) -> None:
    if section == SIMPLE_SECTION:
        if len(content) != 1:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_ADDRESS_REQUIRES_SINGLE_CONTENT")
        for value in content:
            validate_final_value(value)
        return
    invalid: list[str] = []
    for value in content:
        ref_section, ref_entry = find_entry_any(data, value)
        if ref_section is not None and ref_entry is not None:
            continue
        try:
            validate_final_value(value)
        except HTTPException:
            invalid.append(value)
    if invalid:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_ALIAS_ADDRESS_GROUP_CONTENT")


# Valida una entrada completa antes de crear o actualizar.
# Validates a complete entry before create or update.
def validate_entry(data: dict[str, Any], section: str, entry: dict[str, Any], ignore_uuid: str = "") -> dict[str, Any]:
    ensure_section(section)
    entry = dict(entry)
    entry["name"] = clean_name(str(entry.get("name", "")))
    entry["content"] = normalize_content(entry.get("content", []))
    ensure_unique_name(data, entry["name"], ignore_uuid=ignore_uuid)
    validate_content(data, section, entry["content"])
    return entry


# Inserta o actualiza una entrada preservando UUID en edición.
# Inserts or updates an entry while preserving UUID on edits.
def set_entry(data: dict[str, Any], section: str, entry: dict[str, Any], existing_uuid: str = "") -> dict[str, Any]:
    ensure_section(section)
    section_map = data.setdefault(section, {})
    if not isinstance(section_map, dict):
        section_map = {}
        data[section] = section_map
    entry = dict(entry)
    if existing_uuid:
        existing = find_entry_by_uuid(data, section, existing_uuid)
        if not existing:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
        entry["id"] = str(existing.get("id", ""))
        uuid = existing_uuid
    else:
        entry["id"] = next_id(data, section)
        uuid = generate_uuid(data, section, str(entry["id"]))
    entry.pop("UUID", None)
    entry = order_entry_uuid(entry, uuid)
    section_map[uuid] = entry
    return entry


# Bloquea borrados que romperían dependencias internas de grupos.
# Blocks deletes that would break internal group dependencies.
def ensure_delete_allowed(data: dict[str, Any], section: str, uuid: str) -> None:
    entry = find_entry_by_uuid(data, section, uuid)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
    name = str(entry.get("name", ""))
    if section == SIMPLE_SECTION:
        for group in section_entries(data, GROUP_SECTION):
            content = normalize_content(group.get("content", []))
            if uuid in content or name in content:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ALIAS_USED_BY_GROUP")


# Elimina una entrada por UUID después de validar sección.
# Deletes an entry by UUID after validating the section.
def delete_entry(data: dict[str, Any], section: str, uuid: str) -> None:
    ensure_section(section)
    if section_from_uuid(uuid) != section:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ALIAS_UUID_SECTION_MISMATCH")
    if uuid not in data.get(section, {}):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
    data[section].pop(uuid, None)


# Resuelve recursivamente alias/grupos hasta contenido final plano.
# Recursively resolves aliases/groups into final flat content.
def resolve_deep_content(data: dict[str, Any], section: str, entry: dict[str, Any], stack: tuple[str, ...] = (), depth: int = 0, max_depth: int = 64) -> list[str]:
    if depth > max_depth:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ALIAS_RECURSION_LIMIT_EXCEEDED")
    uuid = str(entry.get("UUID", ""))
    if uuid and uuid in stack:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ALIAS_RECURSION_DETECTED")
    resolved: list[str] = []
    seen: set[str] = set()
    next_stack = stack + ((uuid,) if uuid else ())
    for value in normalize_content(entry.get("content", [])):
        ref_section, ref_entry = find_entry_any(data, value)
        if ref_section is not None and ref_entry is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_REFERENCE_NOT_FOUND")
        if ref_section and ref_entry:
            for deep_value in resolve_deep_content(data, ref_section, ref_entry, next_stack, depth + 1, max_depth):
                _append_unique(resolved, seen, deep_value)
        else:
            _append_unique(resolved, seen, value)
    return resolved


# Construye la respuesta deep_translate con nombres y contenido final.
# Builds the deep_translate response with names and final content.
def deep_entry_to_response(data: dict[str, Any], section: str, entry: dict[str, Any]) -> dict[str, Any]:
    response: dict[str, Any] = {"UUID": str(entry.get("UUID", "")), "section": section, "name": str(entry.get("name", ""))}
    content = normalize_content(entry.get("content", []))
    deep_content = resolve_deep_content(data, section, entry)
    if section == GROUP_SECTION:
        content_names: list[str] = []
        seen_names: set[str] = set()
        for value in content:
            ref_section, ref_entry = find_entry_any(data, value)
            if ref_section is not None and ref_entry is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_REFERENCE_NOT_FOUND")
            display = str(ref_entry.get("name", "")) if ref_entry else value
            _append_unique(content_names, seen_names, display)
        response["content_names"] = content_names
        response["deep_content"] = deep_content
    else:
        response["content"] = content
        response["deep_content"] = deep_content
    return response

# Limpia contenido IP profundo quitando duplicados y subredes cubiertas.
# Sanitizes deep IP content by removing duplicates and covered subnets.
def sanitize_deep_ip_content(values: list[str]) -> list[str]:
    normalized: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
    seen_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for value in values:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
        if network in seen_networks:
            continue
        seen_networks.add(network)
        if "/" not in str(value).strip() and network.prefixlen == network.max_prefixlen:
            display = str(network.network_address)
        else:
            display = str(network)
        normalized.append((network, display))

    sanitized: list[str] = []
    for network, display in normalized:
        covered = any(
            network.version == other.version and network != other and network.subnet_of(other)
            for other, _ in normalized
        )
        if not covered:
            sanitized.append(display)
    return sanitized


# Construye deep_translate_sanitized con contenido IP final depurado.
# Builds deep_translate_sanitized with sanitized final IP content.
def deep_entry_to_sanitized_response(data: dict[str, Any], section: str, entry: dict[str, Any]) -> dict[str, Any]:
    response = deep_entry_to_response(data, section, entry)
    response["deep_content_sanitized"] = sanitize_deep_ip_content(response["deep_content"])
    return response

