"""Router HTTP del módulo Routing."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.routing.schemas import ModuleStatus, RoutingDataResponse, RoutingReloadResponse
from modules.routing.service import read_routes, reload_routes

router = APIRouter(prefix="/routing", tags=["routing"])


@router.get("/status", response_model=ModuleStatus, summary="Routing status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que Routing responde."""
    return {"status": "ok", "module": "routing", "user": user["user_name"]}


@router.get("", response_model=RoutingDataResponse, summary="Read routing snapshot")
def read_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lee /var/lib/praesidium/state/routes/routes.json."""
    return read_routes()


@router.post("/reload", response_model=RoutingReloadResponse, summary="Reload system routing snapshot")
def reload_endpoint(user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Ejecuta el extractor controlado de rutas del sistema."""
    return reload_routes()
