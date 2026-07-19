"""
Identificadores internos de Praesidium FastAPI.
Praesidium FastAPI internal identifiers.

Los UUID internos NO son UUID RFC4122: siguen el formato histórico de
Praesidium para identificar objetos de forma inequívoca.
Internal UUIDs are NOT RFC4122 UUIDs: they follow Praesidium's historical
format for unambiguous object identification.
"""

from __future__ import annotations

import random
import re
from datetime import datetime, timezone


# Prefijos oficiales detectados/aceptados para objetos Praesidium.
# Official prefixes detected/accepted for Praesidium objects.
ALLOWED_UUID_PREFIXES: frozenset[str] = frozenset(
    {
        "aliasad",
        "aliagroup",
        "aliaser",
        "aliassergroup",
        "bpf",
        "certtls",
        "configlogsystem",
        "dnsmasq",
        "scopes",
        "dhcpres",
        "vlan",
        "bond",
        "wifi",
        "wgsite",
        "wgserv",
        "wgclient",
        "bridge",
        "ethernet",
        "listenerapache",
        "managementnetworks",
        "nft",
        "passpolicy",
        "servicesstatus",
        "users",
    }
)

_PREFIX_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_OBJECT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_INTERNAL_UUID_RE = re.compile(
    r"^(?P<prefix>[A-Za-z0-9_]+)-(?P<object_id>[^-]+)-(?P<timestamp>\d{17})-(?P<random4>\d{4})$"
)


class IdentifierError(ValueError):
    """Error de generación/validación de identificadores internos."""


def _validate_prefix(prefix: str) -> str:
    """Valida el prefijo oficial. / Validate official prefix."""
    clean = str(prefix).strip()
    if not _PREFIX_RE.fullmatch(clean):
        raise IdentifierError("INVALID_UUID_PREFIX")
    if clean not in ALLOWED_UUID_PREFIXES:
        raise IdentifierError("UNKNOWN_UUID_PREFIX")
    return clean


def _validate_object_id(object_id: str) -> str:
    """Valida el id del objeto. / Validate object id."""
    clean = str(object_id).strip()
    if not clean or not _OBJECT_ID_RE.fullmatch(clean):
        raise IdentifierError("INVALID_UUID_OBJECT_ID")
    return clean


def timestamp_for_internal_uuid() -> str:
    """
    Devuelve timestamp UTC con milisegundos sin separadores.
    Return UTC timestamp with milliseconds and no separators.

    Formato:
        YYYYMMDDHHMMSSmmm
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d%H%M%S") + f"{now.microsecond // 1000:03d}"


def generate_internal_uuid(prefix: str, object_id: str) -> str:
    """
    Genera UUID interno Praesidium.
    Generate Praesidium internal UUID.

    Formato:
        <prefix>-<id>-<timestamp>-<random4>

    Ejemplo:
        users-4-19700101000000000-9764
    """
    clean_prefix = _validate_prefix(prefix)
    clean_object_id = _validate_object_id(object_id)
    random_suffix = f"{random.randint(0, 9999):04d}"
    return f"{clean_prefix}-{clean_object_id}-{timestamp_for_internal_uuid()}-{random_suffix}"


def generate_unique_internal_uuid(
    prefix: str,
    object_id: str,
    existing_uuids: set[str],
    max_attempts: int = 20,
) -> str:
    """
    Genera UUID interno evitando colisiones conocidas.
    Generate internal UUID avoiding known collisions.
    """
    known = set(existing_uuids)
    for _ in range(max_attempts):
        candidate = generate_internal_uuid(prefix, object_id)
        if candidate not in known:
            return candidate
    raise IdentifierError("UNABLE_TO_GENERATE_UNIQUE_UUID")


def parse_internal_uuid(value: str) -> dict[str, str]:
    """
    Divide y valida un UUID interno Praesidium.
    Split and validate a Praesidium internal UUID.
    """
    match = _INTERNAL_UUID_RE.fullmatch(str(value).strip())
    if not match:
        raise IdentifierError("INVALID_INTERNAL_UUID")
    prefix = _validate_prefix(match.group("prefix"))
    return {
        "prefix": prefix,
        "object_id": match.group("object_id"),
        "timestamp": match.group("timestamp"),
        "random4": match.group("random4"),
    }


def is_internal_uuid(value: str) -> bool:
    """Indica si el valor es un UUID interno válido. / Check if value is valid."""
    try:
        parse_internal_uuid(value)
    except IdentifierError:
        return False
    return True
