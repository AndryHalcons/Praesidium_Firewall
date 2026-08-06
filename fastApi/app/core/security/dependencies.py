"""
Dependencias de autenticación/autorización FastAPI.
FastAPI authentication/authorization dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.security.tokens import decode_access_token
from modules.auth.service import is_token_revoked
from modules.users.repository import find_user_by_username, read_users_config


bearer_scheme = HTTPBearer(auto_error=False)


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _policy(data: dict[str, Any]) -> dict[str, Any]:
    defaults = {"password_expiration_days": "90", "force_password_change_on_next_login": "false", "force_password_change_since": ""}
    table = data.get("table_password_policy", [])
    if isinstance(table, list) and table and isinstance(table[0], dict):
        defaults.update(table[0])
    return defaults


def _password_change_reason(user: dict[str, Any], data: dict[str, Any]) -> str:
    policy = _policy(data)
    if str(user.get("force_password_change", "false")).lower() == "true":
        return "force"
    if str(policy.get("force_password_change_on_next_login", "false")).lower() == "true":
        force_since = _parse_time(str(policy.get("force_password_change_since", "")))
        changed_at = _parse_time(str(user.get("password_changed_at", "")))
        if force_since is not None and (changed_at is None or changed_at < force_since):
            return "force"
    try:
        expiration_days = int(policy.get("password_expiration_days", 0))
    except (TypeError, ValueError):
        expiration_days = 0
    changed_at = _parse_time(str(user.get("password_changed_at", "")))
    if expiration_days > 0 and (changed_at is None or (datetime.now(timezone.utc) - changed_at).total_seconds() > expiration_days * 86400):
        return "expired"
    return ""


def current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]) -> dict[str, str]:
    """Devuelve usuario autenticado actual desde running/users.json."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="AUTH_REQUIRED")
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="INVALID_TOKEN") from exc
    username = str(payload.get("sub") or "")
    jti = str(payload.get("jti") or "")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="INVALID_TOKEN")
    if is_token_revoked(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="TOKEN_REVOKED")
    data = read_users_config("running")
    user = find_user_by_username(username, "running")
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="USER_NOT_FOUND")
    reason = _password_change_reason(user, data)
    return {
        "id": str(user.get("id", "")),
        "UUID": str(user.get("UUID", "")),
        "user_name": str(user.get("user_name", "")),
        "user_role": str(user.get("user_role", "")),
        "user_language": str(user.get("user_language", "")),
        "password_change_required": "true" if reason else "false",
        "password_change_reason": reason,
        "__token_jti": jti,
        "__token_exp": str(payload.get("exp") or "0"),
    }


def current_active_user(user: Annotated[dict[str, str], Depends(current_user)]) -> dict[str, str]:
    """Bloquea endpoints normales si requiere cambio de contraseña."""
    if user.get("password_change_required") == "true":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PASSWORD_CHANGE_REQUIRED")
    return user


def require_admin(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Exige rol admin. / Require admin role."""
    if user.get("user_role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ADMIN_REQUIRED")
    return user
