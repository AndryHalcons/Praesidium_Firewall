"""Router HTTP del módulo Monitor Session."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.monitor_session.schemas import (
    ModuleStatus,
    SessionColumnsResponse,
    SessionCommandRequest,
    SessionCommandResponse,
    SessionListResponse,
    SessionRefreshResponse,
)
from modules.monitor_session.service import COLUMNS, read_rows, refresh_snapshot, run_command

router = APIRouter(prefix="/monitor-session", tags=["monitor-session"])


@router.get("/status", response_model=ModuleStatus, summary="Monitor Session status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que Monitor Session responde."""
    return {"status": "ok", "module": "monitor_session", "user": user["user_name"]}


@router.get("/columns", response_model=SessionColumnsResponse, summary="List Monitor Session columns")
def columns_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, list[str]]:
    """Lista columnas de la tabla conntrack."""
    return {"columns": COLUMNS}


@router.get("/sessions", response_model=SessionListResponse, summary="List current user conntrack snapshot")
def sessions_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    """Lee el snapshot XML conntrack del usuario autenticado."""
    rows, has_snapshot = read_rows(user["user_name"])
    return {"rows": rows, "has_snapshot": has_snapshot}


@router.post("/run", response_model=SessionCommandResponse, summary="Run controlled conntrack action")
def run_endpoint(payload: SessionCommandRequest, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    """Ejecuta acción conntrack validada; destructivas requieren admin dentro del servicio."""
    return run_command(payload, user)


@router.post("/refresh", response_model=SessionRefreshResponse, summary="Refresh current user conntrack snapshot")
def refresh_endpoint(user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    """Refresca el snapshot conntrack clásico usando -L."""
    return refresh_snapshot(user)
