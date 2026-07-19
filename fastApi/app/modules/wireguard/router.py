"""Router HTTP del módulo WireGuard."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response

from core.security.dependencies import current_active_user, require_admin
from modules.wireguard.schemas import ModuleStatus, WireGuardConfigResponse, WireGuardEntryResponse, WireGuardMutationResponse, WireGuardRuleRequest, WireGuardSectionResponse
from modules.wireguard.service import build_bundle, build_client_config, create_entry, delete_entry, download_filename, generate_qr_png, get_entry, list_section, masked_config, update_entry

router = APIRouter(prefix="/wireguard", tags=["wireguard"])


def _fallback_host(request: Request) -> str:
    """Extrae Host para export de cliente cuando no hay public_endpoint."""
    return request.headers.get("host", "")


def _list(section: str) -> dict[str, Any]:
    return {"section": section, "entries": list_section(section)}


def _get(section: str, name: str) -> dict[str, Any]:
    entry = get_entry(section, name)
    response_name = str(entry.get("name", name)) if section in {"site_to_site", "remote_access", "remote_clients"} else name
    return {"section": section, "name": response_name, "entry": entry}


@router.get("/status", response_model=ModuleStatus, summary="WireGuard status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que WireGuard responde.

    Formato:
    ```text
    GET /api/v1/wireguard/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/status
    ```
    """
    return {"status": "ok", "module": "wireguard", "user": user["user_name"]}


@router.get("", response_model=WireGuardConfigResponse, summary="List WireGuard config")
def list_config_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista configuración WireGuard enmascarada.

    Formato:
    ```text
    GET /api/v1/wireguard
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard
    ```
    """
    return {"config": masked_config()}


@router.get("/site-to-site", response_model=WireGuardSectionResponse, summary="List site-to-site tunnels")
def list_site_to_site_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista túneles sede-a-sede.

    Formato:
    ```text
    GET /api/v1/wireguard/site-to-site
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/site-to-site
    ```
    """
    return _list("site_to_site")


@router.post("/site-to-site", response_model=WireGuardMutationResponse, summary="Create site-to-site tunnel")
def create_site_to_site_endpoint(payload: WireGuardRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea un túnel sede-a-sede.

    Formato:
    ```text
    POST /api/v1/wireguard/site-to-site
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/wireguard/site-to-site
    ```
    """
    return create_entry("site_to_site", payload.rule)


@router.get("/site-to-site/{uuid}", response_model=WireGuardEntryResponse, summary="Get site-to-site tunnel")
def get_site_to_site_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta un túnel sede-a-sede.

    Formato:
    ```text
    GET /api/v1/wireguard/site-to-site/{uuid}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/site-to-site/wgsite-1-19700101000000000-0000
    ```
    """
    return _get("site_to_site", uuid)


@router.patch("/site-to-site/{uuid}", response_model=WireGuardMutationResponse, summary="Update site-to-site tunnel")
def update_site_to_site_endpoint(uuid: str, payload: WireGuardRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza un túnel sede-a-sede.

    Formato:
    ```text
    PATCH /api/v1/wireguard/site-to-site/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/wireguard/site-to-site/wgsite-1-19700101000000000-0000
    ```
    """
    return update_entry("site_to_site", uuid, payload.rule)


@router.delete("/site-to-site/{uuid}", response_model=WireGuardMutationResponse, summary="Delete site-to-site tunnel")
def delete_site_to_site_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra un túnel sede-a-sede.

    Formato:
    ```text
    DELETE /api/v1/wireguard/site-to-site/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/wireguard/site-to-site/wgsite-1-19700101000000000-0000
    ```
    """
    return delete_entry("site_to_site", uuid)


@router.get("/remote-access", response_model=WireGuardSectionResponse, summary="List remote-access servers")
def list_remote_access_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista servidores de acceso remoto.

    Formato:
    ```text
    GET /api/v1/wireguard/remote-access
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/remote-access
    ```
    """
    return _list("remote_access")


@router.post("/remote-access", response_model=WireGuardMutationResponse, summary="Create remote-access server")
def create_remote_access_endpoint(payload: WireGuardRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea un servidor de acceso remoto.

    Formato:
    ```text
    POST /api/v1/wireguard/remote-access
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/wireguard/remote-access
    ```
    """
    return create_entry("remote_access", payload.rule)


@router.get("/remote-access/{uuid}", response_model=WireGuardEntryResponse, summary="Get remote-access server")
def get_remote_access_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta un servidor de acceso remoto.

    Formato:
    ```text
    GET /api/v1/wireguard/remote-access/{uuid}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/remote-access/wgserv-1-19700101000000000-0000
    ```
    """
    return _get("remote_access", uuid)


@router.patch("/remote-access/{uuid}", response_model=WireGuardMutationResponse, summary="Update remote-access server")
def update_remote_access_endpoint(uuid: str, payload: WireGuardRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza un servidor de acceso remoto.

    Formato:
    ```text
    PATCH /api/v1/wireguard/remote-access/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/wireguard/remote-access/wgserv-1-19700101000000000-0000
    ```
    """
    return update_entry("remote_access", uuid, payload.rule)


@router.delete("/remote-access/{uuid}", response_model=WireGuardMutationResponse, summary="Delete remote-access server")
def delete_remote_access_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra un servidor de acceso remoto.

    Formato:
    ```text
    DELETE /api/v1/wireguard/remote-access/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/wireguard/remote-access/wgserv-1-19700101000000000-0000
    ```
    """
    return delete_entry("remote_access", uuid)


@router.get("/remote-clients", response_model=WireGuardSectionResponse, summary="List remote clients")
def list_remote_clients_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista clientes remotos.

    Formato:
    ```text
    GET /api/v1/wireguard/remote-clients
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/remote-clients
    ```
    """
    return _list("remote_clients")


@router.post("/remote-clients", response_model=WireGuardMutationResponse, summary="Create remote client")
def create_remote_client_endpoint(payload: WireGuardRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea un cliente remoto.

    Formato:
    ```text
    POST /api/v1/wireguard/remote-clients
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/wireguard/remote-clients
    ```
    """
    return create_entry("remote_clients", payload.rule)


@router.get("/remote-clients/{uuid}", response_model=WireGuardEntryResponse, summary="Get remote client")
def get_remote_client_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta un cliente remoto.

    Formato:
    ```text
    GET /api/v1/wireguard/remote-clients/{uuid}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/remote-clients/wgclient-1-19700101000000000-0000
    ```
    """
    return _get("remote_clients", uuid)


@router.patch("/remote-clients/{uuid}", response_model=WireGuardMutationResponse, summary="Update remote client")
def update_remote_client_endpoint(uuid: str, payload: WireGuardRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza un cliente remoto.

    Formato:
    ```text
    PATCH /api/v1/wireguard/remote-clients/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/wireguard/remote-clients/wgclient-1-19700101000000000-0000
    ```
    """
    return update_entry("remote_clients", uuid, payload.rule)


@router.delete("/remote-clients/{uuid}", response_model=WireGuardMutationResponse, summary="Delete remote client")
def delete_remote_client_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra un cliente remoto.

    Formato:
    ```text
    DELETE /api/v1/wireguard/remote-clients/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/wireguard/remote-clients/wgclient-1-19700101000000000-0000
    ```
    """
    return delete_entry("remote_clients", uuid)


@router.get("/remote-clients/{uuid}/config", summary="Download WireGuard client config")
def download_client_config_endpoint(uuid: str, request: Request, user: Annotated[dict[str, str], Depends(require_admin)]) -> Response:
    """Descarga el .conf de un cliente.

    Formato:
    ```text
    GET /api/v1/wireguard/remote-clients/{uuid}/config
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/remote-clients/wgclient-1-19700101000000000-0000/config
    ```
    """
    client = get_entry("remote_clients", uuid)
    display_name = str(client.get("name", uuid))
    content = build_client_config(uuid, _fallback_host(request))
    headers = {"Content-Disposition": f'attachment; filename="{download_filename(display_name, "conf")}"', "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
    return Response(content=content, media_type="application/octet-stream", headers=headers)


@router.get("/remote-clients/{uuid}/qr", summary="Download WireGuard client QR")
def download_client_qr_endpoint(uuid: str, request: Request, user: Annotated[dict[str, str], Depends(require_admin)]) -> Response:
    """Descarga QR PNG de un cliente.

    Formato:
    ```text
    GET /api/v1/wireguard/remote-clients/{uuid}/qr
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/remote-clients/wgclient-1-19700101000000000-0000/qr
    ```
    """
    client = get_entry("remote_clients", uuid)
    display_name = str(client.get("name", uuid))
    config_text = build_client_config(uuid, _fallback_host(request))
    png = generate_qr_png(config_text)
    headers = {"Content-Disposition": f'attachment; filename="{download_filename(display_name, "png")}"', "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
    return Response(content=png, media_type="image/png", headers=headers)


@router.get("/remote-clients/{uuid}/bundle", summary="Download WireGuard client bundle")
def download_client_bundle_endpoint(uuid: str, request: Request, user: Annotated[dict[str, str], Depends(require_admin)]) -> Response:
    """Descarga ZIP con .conf y QR.

    Formato:
    ```text
    GET /api/v1/wireguard/remote-clients/{uuid}/bundle
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/wireguard/remote-clients/wgclient-1-19700101000000000-0000/bundle
    ```
    """
    client = get_entry("remote_clients", uuid)
    display_name = str(client.get("name", uuid))
    bundle = build_bundle(uuid, _fallback_host(request))
    headers = {"Content-Disposition": f'attachment; filename="{download_filename(display_name, "zip")}"', "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"}
    return Response(content=bundle, media_type="application/zip", headers=headers)
