"""
Schemas del módulo Password Policy.
Password Policy module schemas.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PasswordPolicyPublic(BaseModel):
    """Política pública: id/UUID/force_since visibles pero no editables."""

    id: str = "1"
    UUID: str = ""
    password_min_length: str
    password_require_uppercase: str
    password_require_lowercase: str
    password_require_number: str
    password_require_symbol: str
    password_expiration_days: str
    password_history_count: str
    password_min_age_days: str
    login_max_failed_attempts: str
    login_lockout_minutes: str
    login_failed_window_minutes: str
    force_password_change_on_next_login: str
    force_password_change_for_new_users: str
    password_disallow_username: str
    password_disallow_common_passwords: str
    force_password_change_since: str = ""


class PasswordPolicyUpdate(BaseModel):
    """Edición de política: no acepta id/UUID/force_password_change_since."""

    model_config = ConfigDict(extra="forbid")

    password_min_length: str | None = None
    password_require_uppercase: str | None = None
    password_require_lowercase: str | None = None
    password_require_number: str | None = None
    password_require_symbol: str | None = None
    password_expiration_days: str | None = None
    password_history_count: str | None = None
    password_min_age_days: str | None = None
    login_max_failed_attempts: str | None = None
    login_lockout_minutes: str | None = None
    login_failed_window_minutes: str | None = None
    force_password_change_on_next_login: str | None = None
    force_password_change_for_new_users: str | None = None
    password_disallow_username: str | None = None
    password_disallow_common_passwords: str | None = None


class PasswordPolicyResponse(BaseModel):
    """Respuesta con política. / Policy response."""

    policy: PasswordPolicyPublic
