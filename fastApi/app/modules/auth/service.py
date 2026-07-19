"""
Lógica de autenticación FastAPI.
FastAPI authentication logic.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request, status

from core.security.password import verify_password
from core.security.tokens import create_access_token
from modules.users.repository import find_user_by_username, read_users_config, users_config_lock, write_users_config


def _policy(data: dict[str, Any]) -> dict[str, Any]:
    """Política con defaults. / Policy with defaults."""
    defaults = {
        "password_expiration_days": "90",
        "login_max_failed_attempts": "5",
        "login_lockout_minutes": "30",
        "login_failed_window_minutes": "15",
        "force_password_change_on_next_login": "false",
        "force_password_change_since": "",
    }
    table = data.get("table_password_policy", [])
    if isinstance(table, list) and table and isinstance(table[0], dict):
        defaults.update(table[0])
    return defaults


def _policy_int(policy: dict[str, Any], key: str, default: int) -> int:
    """Entero de política. / Policy integer."""
    try:
        return int(policy.get(key, default))
    except (TypeError, ValueError):
        return default


def _policy_bool(policy: dict[str, Any], key: str) -> bool:
    """Booleano textual de política. / Textual policy boolean."""
    return str(policy.get(key, "false")).strip().lower() == "true"


def _client_ip(request: Request) -> str:
    """IP origen directa. / Direct source IP."""
    return request.client.host if request.client else "unknown"


def _attempts(data: dict[str, Any], client_ip: str) -> dict[str, str]:
    """Obtiene intentos por IP. / Get per-IP attempts."""
    for entry in data.get("table_login_attempts", []) or []:
        if str(entry.get("client_ip", "")) == client_ip:
            return dict(entry)
    return {"client_ip": client_ip, "usernames": "", "failed_count": "0", "first_failed_at": "", "locked_until": ""}


def _add_attempt_username(attempts: dict[str, str], username: str) -> None:
    """Guarda usernames intentados como auditoría, sin afectar auth/bloqueo. / Store attempted usernames as audit data without affecting auth/lockout."""
    attempted = str(username).strip()
    if not attempted:
        return
    current = [value.strip() for value in str(attempts.get("usernames", "")).split(",") if value.strip()]
    if attempted not in current:
        current.append(attempted)
    attempts["usernames"] = ",".join(current)


def _parse_time(value: str) -> datetime | None:
    """Parsea ISO/c date. / Parse ISO/c date."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_locked(attempts: dict[str, str]) -> bool:
    """Comprueba bloqueo temporal. / Check temporary lockout."""
    locked_until = _parse_time(str(attempts.get("locked_until", "")))
    return locked_until is not None and locked_until > datetime.now(timezone.utc)


def _save_attempts(data: dict[str, Any], attempts: dict[str, str]) -> None:
    """Guarda intentos por IP. / Save per-IP attempts."""
    rows = data.get("table_login_attempts", [])
    if not isinstance(rows, list):
        rows = []
    updated = False
    for index, entry in enumerate(rows):
        if str(entry.get("client_ip", "")) == attempts["client_ip"]:
            rows[index] = attempts
            updated = True
            break
    if not updated:
        rows.append(attempts)
    data["table_login_attempts"] = rows
    write_users_config(data, "running")


def _clear_attempts(data: dict[str, Any], client_ip: str) -> None:
    """Limpia fallos tras login correcto. / Clear failures after successful login."""
    rows = data.get("table_login_attempts", [])
    data["table_login_attempts"] = [entry for entry in rows if str(entry.get("client_ip", "")) != client_ip] if isinstance(rows, list) else []
    write_users_config(data, "running")


def _record_failure(data: dict[str, Any], client_ip: str, policy: dict[str, Any], username: str) -> None:
    """Registra fallo y aplica lockout. / Record failure and apply lockout."""
    attempts = _attempts(data, client_ip)
    now = datetime.now(timezone.utc)
    first = _parse_time(str(attempts.get("first_failed_at", "")))
    window_minutes = max(1, _policy_int(policy, "login_failed_window_minutes", 15))
    max_attempts = max(1, _policy_int(policy, "login_max_failed_attempts", 5))
    lockout_minutes = max(0, _policy_int(policy, "login_lockout_minutes", 30))

    if first is None or (now - first).total_seconds() > window_minutes * 60:
        attempts["failed_count"] = "0"
        attempts["first_failed_at"] = now.isoformat()
        attempts["locked_until"] = ""
        attempts["usernames"] = ""

    _add_attempt_username(attempts, username)
    attempts["failed_count"] = str(int(attempts.get("failed_count", "0")) + 1)
    if int(attempts["failed_count"]) >= max_attempts and lockout_minutes > 0:
        attempts["locked_until"] = (now.replace(microsecond=0) + timedelta(minutes=lockout_minutes)).isoformat()
    _save_attempts(data, attempts)


def _password_change_reason(user: dict[str, Any], policy: dict[str, Any]) -> str:
    """Calcula si debe cambiar contraseña. / Calculate password-change requirement."""
    if str(user.get("force_password_change", "false")).lower() == "true":
        return "force"
    if _policy_bool(policy, "force_password_change_on_next_login"):
        force_since = _parse_time(str(policy.get("force_password_change_since", "")))
        changed_at = _parse_time(str(user.get("password_changed_at", "")))
        if force_since is not None and (changed_at is None or changed_at < force_since):
            return "force"
    expiration_days = _policy_int(policy, "password_expiration_days", 0)
    changed_at = _parse_time(str(user.get("password_changed_at", "")))
    if expiration_days > 0 and (changed_at is None or (datetime.now(timezone.utc) - changed_at).total_seconds() > expiration_days * 86400):
        return "expired"
    return ""



def _revoked_tokens(data: dict[str, Any]) -> list[dict[str, str]]:
    """Lista de tokens revocados en running. / Revoked token list in running."""
    rows = data.get("table_revoked_tokens", [])
    return rows if isinstance(rows, list) else []


def is_token_revoked(jti: str) -> bool:
    """Comprueba si el jti está revocado en running/users.json."""
    if not jti:
        return False
    data = read_users_config("running")
    now = datetime.now(timezone.utc).timestamp()
    for row in _revoked_tokens(data):
        if str(row.get("jti", "")) == jti:
            return True
    return False


def revoke_token(jti: str, username: str, exp: int | str) -> None:
    """Revoca token actual hasta su expiración natural."""
    if not jti:
        return
    with users_config_lock("running"):
        data = read_users_config("running")
        rows = _revoked_tokens(data)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        clean_rows = []
        for row in rows:
            try:
                row_exp = int(str(row.get("exp", "0")))
            except ValueError:
                row_exp = 0
            if row_exp > now_ts and str(row.get("jti", "")) != jti:
                clean_rows.append(row)
        clean_rows.append({"jti": jti, "user_name": username, "exp": str(exp), "revoked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat()})
        data["table_revoked_tokens"] = clean_rows
        write_users_config(data, "running")

def login(username: str, password: str, request: Request) -> dict[str, Any]:
    """Autentica usuario y devuelve token. / Authenticate user and return token."""
    with users_config_lock("running"):
        data = read_users_config("running")
        policy = _policy(data)
        client_ip = _client_ip(request)
        attempts = _attempts(data, client_ip)

        if _is_locked(attempts):
            _add_attempt_username(attempts, username)
            _save_attempts(data, attempts)
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="LOGIN_TEMPORARILY_BLOCKED")

        user = find_user_by_username(username, "running")
        if user is None or not verify_password(password, str(user.get("user_pass", ""))):
            _record_failure(data, client_ip, policy, username)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="BAD_CREDENTIALS")

        _clear_attempts(data, client_ip)
        reason = _password_change_reason(user, policy)
        token = create_access_token({"sub": user["user_name"], "role": user.get("user_role", ""), "lang": user.get("user_language", "")})
        return {"access_token": token, "token_type": "bearer", "password_change_required": reason != "", "password_change_reason": reason}
