"""
Schemas Pydantic del módulo Users.
Pydantic schemas for the Users module.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class UserPublic(BaseModel):
    """Usuario expuesto por API sin contraseña. / API user without password."""

    id: str
    UUID: str = ""
    user_name: str
    user_role: str
    user_language: str = ""
    password_changed_at: str = ""
    force_password_change: str = "false"


class UserCreate(BaseModel):
    """Creación de usuario: UUID/password_changed_at son internos."""

    model_config = ConfigDict(extra="forbid")

    user_name: str = Field(min_length=1)
    user_pass: str = Field(min_length=1)
    user_role: str = Field(pattern="^(viewer|admin)$")
    user_language: str = ""
    force_password_change: str | None = None


class UserUpdate(BaseModel):
    """Edición de usuario: no permite UUID/password_changed_at/user_pass."""

    model_config = ConfigDict(extra="forbid")

    user_name: str | None = Field(default=None, min_length=1)
    user_role: str | None = Field(default=None, pattern="^(viewer|admin)$")
    user_language: str | None = None
    force_password_change: str | None = None


class PasswordChangeRequest(BaseModel):
    """Cambio de contraseña administrativo con confirmación del admin."""

    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=1)
    confirm_password: str = Field(min_length=1)
    force_password_change: str | None = None


class UsersListResponse(BaseModel):
    """Respuesta de listado de usuarios. / Users list response."""

    users: list[UserPublic]


class ModuleStatus(BaseModel):
    """Estado mínimo del módulo. / Minimal module status."""

    status: str
    module: str
