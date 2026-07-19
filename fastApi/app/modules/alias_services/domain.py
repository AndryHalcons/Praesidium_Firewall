"""
Reglas de dominio de Alias Services.
Alias Services domain rules.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import HTTPException, status

from core.identifiers import generate_unique_internal_uuid

SIMPLE_SECTION = "alias_service"
GROUP_SECTION = "alias_service_group"
SECTIONS = (SIMPLE_SECTION, GROUP_SECTION)
UUID_PREFIXES = {SIMPLE_SECTION: "aliaser", GROUP_SECTION: "aliassergroup"}
VALUE_KIND = "port"


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
    clean = str(value).strip()
    if "-" in clean:
        start_s, end_s = clean.split("-", 1)
        if not start_s.strip().isdigit() or not end_s.strip().isdigit():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_PORT_RANGE")
        start = int(start_s.strip())
        end = int(end_s.strip())
        if start < 1 or end > 65535 or start > end:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_PORT_RANGE")
        return
    if not clean.isdigit() or int(clean) < 1 or int(clean) > 65535:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_PORT")


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


def validate_mixed_service_item(data: dict[str, Any], item: Any, *, allow_groups: bool = True, stack: tuple[str, ...] = (), depth: int = 0, max_depth: int = 64) -> None:
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
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_PORT_OR_ALIAS")
    if ref_section == GROUP_SECTION and not allow_groups:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_SERVICE_GROUP_NOT_ALLOWED")
    uuid = str(ref_entry.get("UUID", ""))
    if uuid and uuid in stack:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="ALIAS_RECURSION_DETECTED")
    next_stack = stack + ((uuid,) if uuid else ())
    for child in mixed_reference_items(ref_entry.get("content", [])):
        validate_mixed_service_item(data, child, allow_groups=allow_groups, stack=next_stack, depth=depth + 1, max_depth=max_depth)


def validate_mixed_service_references(data: dict[str, Any], value: Any, *, allow_groups: bool = True, allow_multiple: bool = True) -> None:
    items = mixed_reference_items(value)
    if not items:
        return
    if not allow_multiple and len(items) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_PORT_OR_ALIAS_ALLOWED")
    for item in items:
        validate_mixed_service_item(data, item, allow_groups=allow_groups)


# Comprueba que un literal o alias simple resuelva a un único puerto, nunca a un rango.
# Checks that a literal or simple alias resolves to one port, never to a range.
def single_port_check(data: dict[str, Any], value: Any) -> None:
    items = mixed_reference_items(value)
    if len(items) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_PORT_OR_ALIAS_ALLOWED")

    item = items[0]
    if isinstance(item, str):
        candidate = item.strip()
        if candidate.isdigit() and 1 <= int(candidate) <= 65535:
            return

    ref_section, ref_entry = find_entry_reference(data, item)
    if ref_section is not None and ref_entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_REFERENCE_NOT_FOUND")
    if ref_section is None or ref_entry is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_PORT_OR_ALIAS")
    if ref_section != SIMPLE_SECTION:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_SERVICE_GROUP_NOT_ALLOWED")

    resolved = resolve_deep_content(data, ref_section, ref_entry)
    if len(resolved) != 1:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ONLY_ONE_PORT_OR_ALIAS_ALLOWED")
    port_value = str(resolved[0]).strip()
    if not port_value.isdigit() or int(port_value) < 1 or int(port_value) > 65535:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="SINGLE_PORT_REQUIRED")


# Valida content según si es alias simple o grupo.
# Validates content depending on simple alias or group.
def validate_content(data: dict[str, Any], section: str, content: list[str]) -> None:
    if section == SIMPLE_SECTION:
        if len(content) != 1:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="ALIAS_SERVICE_REQUIRES_SINGLE_CONTENT")
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
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="INVALID_ALIAS_SERVICE_GROUP_CONTENT")


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

# Convierte puerto/rango validado en intervalo numérico.
# Converts a validated port/range into a numeric interval.
def port_value_to_interval(value: str) -> tuple[int, int]:
    clean = str(value).strip()
    validate_final_value(clean)
    if "-" in clean:
        start_s, end_s = clean.split("-", 1)
        return int(start_s.strip()), int(end_s.strip())
    port = int(clean)
    return port, port


# Formatea un intervalo de puertos como puerto o rango.
# Formats a port interval as a port or range.
def interval_to_port_value(start: int, end: int) -> str:
    if start == end:
        return str(start)
    return f"{start}-{end}"


# Limpia contenido service profundo quitando duplicados y compactando rangos.
# Sanitizes deep service content by removing duplicates and compacting ranges.
def sanitize_deep_service_content(values: list[str]) -> list[str]:
    intervals = [port_value_to_interval(value) for value in values]
    intervals.sort(key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if not merged:
            merged.append((start, end))
            continue
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return [interval_to_port_value(start, end) for start, end in merged]


# Construye deep_translate_sanitized con contenido service depurado.
# Builds deep_translate_sanitized with sanitized service content.
def deep_entry_to_sanitized_response(data: dict[str, Any], section: str, entry: dict[str, Any]) -> dict[str, Any]:
    response = deep_entry_to_response(data, section, entry)
    response["deep_content_sanitized"] = sanitize_deep_service_content(response["deep_content"])
    return response

