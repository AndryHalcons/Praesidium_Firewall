"""
Verificación y generación de contraseñas Praesidium.
Praesidium password verification and generation.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError


# ES: Parámetros equivalentes a password_hash() PHP usado en Praesidium legacy.
# EN: Parameters equivalent to PHP password_hash() used in legacy Praesidium.
_ARGON2 = PasswordHasher(memory_cost=65536, time_cost=4, parallelism=1)
_LEGACY_SHA512_RE = re.compile(r"^[A-Fa-f0-9]{128}$")


def is_legacy_sha512(stored_hash: str) -> bool:
    """Detecta hashes SHA-512 legacy. / Detect legacy SHA-512 hashes."""
    return bool(_LEGACY_SHA512_RE.fullmatch(stored_hash or ""))


def hash_password(password: str) -> str:
    """Genera hash Argon2id. / Generate Argon2id hash."""
    return _ARGON2.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifica contraseña contra Argon2id PHP o SHA-512 legacy."""
    if not stored_hash:
        return False

    if is_legacy_sha512(stored_hash):
        calculated = hashlib.sha512(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(calculated.lower(), stored_hash.lower())

    try:
        return _ARGON2.verify(stored_hash, password)
    except (InvalidHashError, VerifyMismatchError, VerificationError):
        return False
