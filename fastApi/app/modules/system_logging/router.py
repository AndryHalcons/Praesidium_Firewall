"""Router HTTP del módulo System Logging."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.system_logging.schemas import (
    JournaldResponse,
    JournaldUpdate,
    ModuleStatus,
    MutationResponse,
    NftablesLogsResponse,
    NftablesLogsUpdate,
    SystemLoggingConfigResponse,
    SystemLogsResponse,
    SystemLogsUpdate,
)
from modules.system_logging.service import read_candidate_config, read_section, update_section

router = APIRouter(prefix="/system-logging", tags=["system-logging"])


@router.get("/status", response_model=ModuleStatus, summary="System Logging status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que System Logging responde.

    Formato:
    ```text
    GET /api/v1/system-logging/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/system-logging/status
    ```
    """
    return {"status": "ok", "module": "system_logging", "user": user["user_name"]}


@router.get("", response_model=SystemLoggingConfigResponse, summary="List System Logging config")
def list_config_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista la configuración candidata de logs.

    Formato:
    ```text
    GET /api/v1/system-logging
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/system-logging
    ```
    """
    return {"config": read_candidate_config()}


@router.get("/journald", response_model=JournaldResponse, summary="Get Journald logging config")
def get_journald_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta la configuración candidata de journald.

    Formato:
    ```text
    GET /api/v1/system-logging/journald
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/system-logging/journald
    ```
    """
    return {"journald": read_section("journald")}


@router.patch("/journald", response_model=MutationResponse, summary="Update Journald logging config")
def update_journald_endpoint(payload: JournaldUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza la configuración candidata de journald.

    Formato:
    ```text
    PATCH /api/v1/system-logging/journald
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/system-logging/journald
    ```

    Body:
    ```json
    {"system_max_use":"250M","compress":true}
    ```
    """
    return update_section("journald", payload)


@router.get("/system-logs", response_model=SystemLogsResponse, summary="Get System Logs config")
def get_system_logs_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta la rotación candidata de logs del sistema.

    Formato:
    ```text
    GET /api/v1/system-logging/system-logs
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/system-logging/system-logs
    ```
    """
    return {"system_logs": read_section("system_logs")}


@router.patch("/system-logs", response_model=MutationResponse, summary="Update System Logs config")
def update_system_logs_endpoint(payload: SystemLogsUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza la rotación candidata de logs del sistema.

    Formato:
    ```text
    PATCH /api/v1/system-logging/system-logs
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/system-logging/system-logs
    ```

    Body:
    ```json
    {"rotation":"weekly","rotate":14,"compress":true}
    ```
    """
    return update_section("system_logs", payload)


@router.get("/nftables-logs", response_model=NftablesLogsResponse, summary="Get Nftables Logs config")
def get_nftables_logs_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta la configuración candidata de logs nftables.

    Formato:
    ```text
    GET /api/v1/system-logging/nftables-logs
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/system-logging/nftables-logs
    ```
    """
    return {"nftables_logs": read_section("nftables_logs")}


@router.patch("/nftables-logs", response_model=MutationResponse, summary="Update Nftables Logs config")
def update_nftables_logs_endpoint(payload: NftablesLogsUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza la configuración candidata de logs nftables.

    Formato:
    ```text
    PATCH /api/v1/system-logging/nftables-logs
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/system-logging/nftables-logs
    ```

    Body:
    ```json
    {"enabled":true,"size":"100M","rotate":7}
    ```
    """
    return update_section("nftables_logs", payload)
