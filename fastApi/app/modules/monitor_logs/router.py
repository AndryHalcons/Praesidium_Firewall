"""Router HTTP del módulo Monitor Logs."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user
from modules.monitor_logs.schemas import ModuleStatus, MonitorLogOptionsResponse, MonitorLogSearchRequest, MonitorLogSearchResponse
from modules.monitor_logs.service import options, search_logs

router = APIRouter(prefix="/monitor-logs", tags=["monitor-logs"])


@router.get("/status", response_model=ModuleStatus, summary="Monitor Logs status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que Monitor Logs responde.

    Formato:
    ```text
    GET /api/v1/monitor-logs/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/monitor-logs/status
    ```
    """
    return {"status": "ok", "module": "monitor_logs", "user": user["user_name"]}


@router.get("/options", response_model=MonitorLogOptionsResponse, summary="List Monitor Logs options")
def options_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista filtros soportados.

    Formato:
    ```text
    GET /api/v1/monitor-logs/options
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/monitor-logs/options
    ```
    """
    return {"options": options()}


@router.post("/search", response_model=MonitorLogSearchResponse, summary="Search firewall logs")
def search_endpoint(payload: MonitorLogSearchRequest, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Busca logs del firewall.

    Formato:
    ```text
    POST /api/v1/monitor-logs/search
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/monitor-logs/search
    ```

    Body:
    ```json
    {"Firewall":"NFTABLES","Start_Date":"1970-01-01","Start_Time":"00:00","End_Date":"1970-01-01","End_Time":"23:59","Max_Records":"100"}
    ```
    """
    return {"logs": search_logs(payload, user["user_name"])}
