"""Router HTTP del módulo Management."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.management.schemas import (
    AllowedSourceCreate,
    AllowedSourceResponse,
    AllowedSourcesResponse,
    AllowedSourceUpdate,
    ListenerResponse,
    ListenerRow,
    ManagementConfigResponse,
    ModuleStatus,
    MutationResponse,
    TlsResponse,
    TlsRow,
)
from modules.management.service import (
    create_allowed_source,
    delete_allowed_source,
    get_allowed_source,
    get_listener,
    get_tls,
    list_allowed_sources,
    public_config,
    update_allowed_source,
    update_listener,
    update_tls,
)

router = APIRouter(prefix="/management", tags=["management"])


@router.get("/status", response_model=ModuleStatus, summary="Management status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que Management responde.

    Formato:
    ```text
    GET /api/v1/management/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/management/status
    ```
    """
    return {"status": "ok", "module": "management", "user": user["user_name"]}


@router.get("", response_model=ManagementConfigResponse, summary="List Management config")
def list_config_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista la configuración candidata de Management.

    Formato:
    ```text
    GET /api/v1/management
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/management
    ```
    """
    return {"config": public_config()}


@router.get("/listener", response_model=ListenerResponse, summary="Get Management listener")
def get_listener_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta el listener HTTPS de gestión.

    Formato:
    ```text
    GET /api/v1/management/listener
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/management/listener
    ```
    """
    return {"listener": get_listener()}


@router.patch("/listener", response_model=MutationResponse, summary="Update Management listener")
def update_listener_endpoint(payload: ListenerRow, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza el listener HTTPS de gestión.

    Formato:
    ```text
    PATCH /api/v1/management/listener
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/management/listener
    ```

    Body:
    ```json
    {"listen_ip":"0.0.0.0","listen_port":"443","server_name":"praesidium.local"}
    ```
    """
    return update_listener(payload.model_dump(exclude_none=True))


@router.get("/tls", response_model=TlsResponse, summary="Get Management TLS")
def get_tls_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta los ficheros TLS de gestión.

    Formato:
    ```text
    GET /api/v1/management/tls
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/management/tls
    ```
    """
    return {"tls": get_tls()}


@router.patch("/tls", response_model=MutationResponse, summary="Update Management TLS")
def update_tls_endpoint(payload: TlsRow, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza los ficheros TLS de gestión.

    Formato:
    ```text
    PATCH /api/v1/management/tls
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/management/tls
    ```

    Body:
    ```json
    {"certificate_file":"praesidium_management_cert.pem","certificate_key":"praesidium_management_key.key","certificate_chain":"praesidium_management_chain.pem"}
    ```
    """
    return update_tls(payload.model_dump(exclude_none=True))


@router.get("/allowed-sources", response_model=AllowedSourcesResponse, summary="List Management allowed sources")
def list_allowed_sources_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista redes permitidas para gestión.

    Formato:
    ```text
    GET /api/v1/management/allowed-sources
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/management/allowed-sources
    ```
    """
    return {"allowed_sources": list_allowed_sources()}


@router.post("/allowed-sources", response_model=MutationResponse, summary="Create Management allowed source")
def create_allowed_source_endpoint(payload: AllowedSourceCreate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una red permitida para gestión.

    Formato:
    ```text
    POST /api/v1/management/allowed-sources
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/management/allowed-sources
    ```

    Body:
    ```json
    {"source_cidr":"192.0.2.0/24","description":"management-lan"}
    ```
    """
    return create_allowed_source(payload.model_dump())


@router.get("/allowed-sources/{source_id}", response_model=AllowedSourceResponse, summary="Get Management allowed source")
def get_allowed_source_endpoint(source_id: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta una red permitida para gestión.

    Formato:
    ```text
    GET /api/v1/management/allowed-sources/{source_id}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/management/allowed-sources/1
    ```
    """
    return {"allowed_source": get_allowed_source(source_id)}


@router.patch("/allowed-sources/{source_id}", response_model=MutationResponse, summary="Update Management allowed source")
def update_allowed_source_endpoint(source_id: str, payload: AllowedSourceUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una red permitida para gestión.

    Formato:
    ```text
    PATCH /api/v1/management/allowed-sources/{source_id}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/management/allowed-sources/1
    ```

    Body:
    ```json
    {"description":"management-anywhere"}
    ```
    """
    return update_allowed_source(source_id, payload.model_dump(exclude_none=True))


@router.delete("/allowed-sources/{source_id}", response_model=MutationResponse, summary="Delete Management allowed source")
def delete_allowed_source_endpoint(source_id: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una red permitida para gestión.

    Formato:
    ```text
    DELETE /api/v1/management/allowed-sources/{source_id}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/management/allowed-sources/4
    ```
    """
    return delete_allowed_source(source_id)
