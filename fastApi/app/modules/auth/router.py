"""
Router HTTP del módulo Auth.
HTTP router for the Auth module.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from core.security.dependencies import current_user
from modules.auth.schemas import ChangeOwnPasswordRequest, LoginRequest, MeResponse, TokenResponse
from modules.auth.service import login, revoke_token
from modules.users.service import change_own_password


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login_endpoint(payload: LoginRequest, request: Request) -> dict[str, object]:
    """Login API con users.json running. / API login using running users.json."""
    return login(payload.username, payload.password, request)


@router.get("/me", response_model=MeResponse)
def me_endpoint(user: Annotated[dict[str, str], Depends(current_user)]) -> dict[str, str]:
    """Devuelve el usuario autenticado aunque requiera cambio de contraseña."""
    return user


@router.post("/change-password", response_model=MeResponse)
def change_own_password_endpoint(payload: ChangeOwnPasswordRequest, user: Annotated[dict[str, str], Depends(current_user)]) -> dict[str, str]:
    """Permite cambiar contraseña propia, incluso si hay cambio obligatorio."""
    changed = change_own_password(
        user["user_name"],
        payload.current_password,
        payload.new_password,
        payload.confirm_password,
        bypass_min_age=user.get("password_change_required") == "true",
    )
    changed["password_change_required"] = "false"
    changed["password_change_reason"] = ""
    return changed


@router.post("/logout")
def logout_endpoint(user: Annotated[dict[str, str], Depends(current_user)]) -> dict[str, str]:
    """Revoca el token Bearer actual en running/users.json."""
    revoke_token(user.get("__token_jti", ""), user["user_name"], user.get("__token_exp", "0"))
    return {"status": "ok", "message": "token revoked", "user": user["user_name"]}
