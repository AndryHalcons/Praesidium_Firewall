"""
Schemas del módulo Auth.
Auth module schemas.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class LoginRequest(BaseModel):
    """Petición de login. / Login request."""

    username: str
    password: str


class ChangeOwnPasswordRequest(BaseModel):
    """Cambio de contraseña del usuario autenticado."""

    model_config = ConfigDict(extra="forbid")

    current_password: str
    new_password: str
    confirm_password: str


class TokenResponse(BaseModel):
    """Respuesta de token. / Token response."""

    access_token: str
    token_type: str = "bearer"
    password_change_required: bool = False
    password_change_reason: str = ""


class MeResponse(BaseModel):
    """Usuario actual. / Current user."""

    id: str
    UUID: str = ""
    user_name: str
    user_role: str
    user_language: str
    password_change_required: str = "false"
    password_change_reason: str = ""
