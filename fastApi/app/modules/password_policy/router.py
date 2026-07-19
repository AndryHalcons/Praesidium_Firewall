"""
Router HTTP del módulo Password Policy.
HTTP router for the Password Policy module.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.password_policy.schemas import PasswordPolicyResponse, PasswordPolicyUpdate
from modules.password_policy.service import clear_force_change, enable_force_change, get_policy, update_policy


router = APIRouter(prefix="/password-policy", tags=["password-policy"])


@router.get("/", response_model=PasswordPolicyResponse)
def get_password_policy_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    """Consulta política candidate. / Read candidate policy."""
    return {"policy": get_policy()}


@router.patch("/", response_model=PasswordPolicyResponse)
def update_password_policy_endpoint(payload: PasswordPolicyUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    """Edita política candidate. / Edit candidate policy."""
    return {"policy": update_policy(payload)}


@router.post("/force-change", response_model=PasswordPolicyResponse)
def force_change_endpoint(user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    """Activa cambio obligatorio global. / Enable global mandatory change."""
    return {"policy": enable_force_change()}


@router.post("/clear-force-change", response_model=PasswordPolicyResponse)
def clear_force_change_endpoint(user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    """Desactiva cambio obligatorio global. / Disable global mandatory change."""
    return {"policy": clear_force_change()}
