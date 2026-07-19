"""
Tokens Bearer/JWT de Praesidium FastAPI.
Praesidium FastAPI Bearer/JWT tokens.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt

from core.config import settings


ALGORITHM = "HS256"


def create_access_token(payload: dict[str, Any], expires_minutes: int | None = None) -> str:
    """
    Crea un token JWT firmado.
    Create a signed JWT token.
    """
    now = datetime.now(timezone.utc)
    ttl = settings.api_token_expires_minutes if expires_minutes is None else expires_minutes
    data = dict(payload)
    data.update({
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl)).timestamp()),
        "jti": uuid4().hex,
    })
    return jwt.encode(data, settings.api_token_secret, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decodifica y valida un token JWT.
    Decode and validate a JWT token.
    """
    return jwt.decode(token, settings.api_token_secret, algorithms=[ALGORITHM])
