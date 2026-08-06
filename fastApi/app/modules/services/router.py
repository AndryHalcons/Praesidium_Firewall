"""Router HTTP del módulo Services."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.services.schemas import ModuleStatus, ServiceEntryResponse, ServiceMutationResponse, ServicesCatalogResponse, ServicesConfigResponse, ServicesRowsResponse, ServicesRuntimeResponse, ServiceUpdateRequest
from modules.services.service import catalog, get_service, read_candidate_config, rows, runtime_statuses, update_service

router = APIRouter(prefix="/services", tags=["services"])


@router.get("/status", response_model=ModuleStatus, summary="Services status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que Services responde.

    Formato:
    ```text
    GET /api/v1/services/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/services/status
    ```
    """
    return {"status": "ok", "module": "services", "user": user["user_name"]}


@router.get("", response_model=ServicesConfigResponse, summary="List Services config")
def list_config_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista la configuración candidata de servicios.

    Formato:
    ```text
    GET /api/v1/services
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/services
    ```
    """
    return {"config": read_candidate_config()}


@router.get("/catalog", response_model=ServicesCatalogResponse, summary="List Services catalog")
def catalog_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista el catálogo fijo de servicios.

    Formato:
    ```text
    GET /api/v1/services/catalog
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/services/catalog
    ```
    """
    return {"catalog": catalog()}


@router.get("/rows", response_model=ServicesRowsResponse, summary="List Services rows")
def rows_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista servicios con estado runtime.

    Formato:
    ```text
    GET /api/v1/services/rows
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/services/rows
    ```
    """
    return {"services": rows()}


@router.get("/runtime", response_model=ServicesRuntimeResponse, summary="Refresh Services runtime")
def runtime_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta el estado runtime actual.

    Formato:
    ```text
    GET /api/v1/services/runtime
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/services/runtime
    ```
    """
    return {"services": runtime_statuses()}


@router.get("/{service_name}", response_model=ServiceEntryResponse, summary="Get Service entry")
def get_service_endpoint(service_name: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta un servicio.

    Formato:
    ```text
    GET /api/v1/services/{service_name}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/services/dnsmasq
    ```
    """
    return {"service_name": service_name, "service": get_service(service_name)}


@router.patch("/{service_name}", response_model=ServiceMutationResponse, summary="Update Service desired state")
def update_service_endpoint(service_name: str, payload: ServiceUpdateRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza desired_enabled en candidate.

    Formato:
    ```text
    PATCH /api/v1/services/{service_name}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/services/dnsmasq
    ```

    Body:
    ```json
    {"desired_enabled":"true"}
    ```
    """
    return update_service(service_name, payload.desired_enabled)
