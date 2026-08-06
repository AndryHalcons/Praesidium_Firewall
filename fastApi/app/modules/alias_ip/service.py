"""
Servicio de Alias IP.
Alias IP service.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

from modules.alias_ip.domain import (
    deep_entry_to_response,
    deep_entry_to_sanitized_response,
    delete_entry,
    ensure_delete_allowed,
    ensure_section,
    entry_to_frontend,
    entry_to_storage,
    find_entry_by_uuid,
    normalize_store,
    section_entries,
    section_from_uuid,
    set_entry,
    validate_entry,
)
from modules.alias_ip.repository import config_lock, read_config, write_config


# Lista entradas visibles de una sección alias.
# Lists visible entries for an alias section.
def list_aliases(section: str) -> list[dict[str, Any]]:
    ensure_section(section)
    data = normalize_store(read_config("candidate"))
    return [entry_to_frontend(data, section, entry) for entry in section_entries(data, section)]


# Devuelve una entrada visible por UUID.
# Returns one visible entry by UUID.
def get_alias(section: str, uuid: str) -> dict[str, Any]:
    ensure_section(section)
    data = normalize_store(read_config("candidate"))
    if section_from_uuid(uuid) != section:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ALIAS_UUID_SECTION_MISMATCH")
    entry = find_entry_by_uuid(data, section, uuid)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
    return entry_to_frontend(data, section, entry)


# Crea una entrada alias en candidate.
# Creates an alias entry in candidate.
def create_alias(section: str, payload: Any) -> dict[str, Any]:
    ensure_section(section)
    with config_lock("candidate"):
        data = normalize_store(read_config("candidate"))
        entry = validate_entry(data, section, {"name": payload.name, "content": payload.content})
        stored = entry_to_storage(data, section, entry)
        created = set_entry(data, section, stored)
        write_config(normalize_store(data), "candidate")
        return entry_to_frontend(data, section, created)


# Actualiza una entrada alias en candidate por UUID.
# Updates an alias entry in candidate by UUID.
def update_alias(section: str, uuid: str, payload: Any) -> dict[str, Any]:
    ensure_section(section)
    with config_lock("candidate"):
        data = normalize_store(read_config("candidate"))
        if section_from_uuid(uuid) != section:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ALIAS_UUID_SECTION_MISMATCH")
        existing = find_entry_by_uuid(data, section, uuid)
        if not existing:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
        merged = dict(existing)
        if payload.name is not None:
            merged["name"] = payload.name
        if payload.content is not None:
            merged["content"] = payload.content
        merged.pop("UUID", None)
        entry = validate_entry(data, section, merged, ignore_uuid=uuid)
        stored = entry_to_storage(data, section, entry)
        updated = set_entry(data, section, stored, existing_uuid=uuid)
        write_config(normalize_store(data), "candidate")
        return entry_to_frontend(data, section, updated)


# Borra una entrada alias de candidate por UUID.
# Deletes an alias entry from candidate by UUID.
def delete_alias(section: str, uuid: str) -> dict[str, str]:
    ensure_section(section)
    with config_lock("candidate"):
        data = normalize_store(read_config("candidate"))
        ensure_delete_allowed(data, section, uuid)
        delete_entry(data, section, uuid)
        write_config(normalize_store(data), "candidate")
    return {"status": "deleted", "UUID": uuid}


# Traduce UUID a sección y nombre visible.
# Translates UUID into section and visible name.
def translate_alias(uuid: str) -> dict[str, str]:
    section = section_from_uuid(uuid)
    if section is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="INVALID_ALIAS_UUID")
    data = normalize_store(read_config("candidate"))
    entry = find_entry_by_uuid(data, section, uuid)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
    return {"UUID": uuid, "section": section, "name": str(entry.get("name", ""))}


# Resuelve UUID a contenido final usando deep_translate.
# Resolves UUID to final content using deep_translate.
def deep_translate_alias(uuid: str) -> dict[str, Any]:
    section = section_from_uuid(uuid)
    if section is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="INVALID_ALIAS_UUID")
    data = normalize_store(read_config("candidate"))
    entry = find_entry_by_uuid(data, section, uuid)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
    return deep_entry_to_response(data, section, entry)


# Resuelve UUID a contenido final IP saneado usando deep_translate_sanitized.
# Resolves UUID to sanitized final IP content using deep_translate_sanitized.
def deep_translate_sanitized_alias(uuid: str) -> dict[str, Any]:
    section = section_from_uuid(uuid)
    if section is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="INVALID_ALIAS_UUID")
    data = normalize_store(read_config("candidate"))
    entry = find_entry_by_uuid(data, section, uuid)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ALIAS_NOT_FOUND")
    return deep_entry_to_sanitized_response(data, section, entry)
