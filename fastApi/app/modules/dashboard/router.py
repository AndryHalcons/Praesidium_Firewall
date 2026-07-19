"""Router HTTP del módulo Dashboard."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user
from modules.dashboard.schemas import DashboardStatsResponse, ModuleStatus
from modules.dashboard.service import dashboard_stats

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/status", response_model=ModuleStatus, summary="Dashboard status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Devuelve el estado del módulo Dashboard."""
    return {"status": "ok", "module": "dashboard", "user": user["user_name"]}


@router.get("/stats", response_model=DashboardStatsResponse, summary="Get dashboard metrics")
def stats_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    """Devuelve métricas actuales del sistema para el dashboard."""
    return dashboard_stats()
