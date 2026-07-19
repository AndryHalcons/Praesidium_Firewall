"""Router admin para login_attempts reales en running."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from core.security.dependencies import require_admin
from modules.login_attempts.schemas import LoginAttemptDeleteResponse, LoginAttemptsResponse
from modules.login_attempts.service import delete_login_attempt, list_login_attempts


router = APIRouter(prefix="/login-attempts", tags=["login_attempts"])


@router.get("/", response_model=LoginAttemptsResponse)
def list_login_attempts_endpoint(user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    """Lista intentos/bloqueos reales desde running/users.json."""
    return {"attempts": list_login_attempts()}


@router.delete("/{client_ip}", response_model=LoginAttemptDeleteResponse)
def delete_login_attempt_endpoint(client_ip: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, str]:
    """Desbloquea IP eliminando su fila en running/users.json."""
    return delete_login_attempt(client_ip)
