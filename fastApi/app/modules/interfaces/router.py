"""
Router HTTP del módulo Interfaces.
Interfaces module HTTP router.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.interfaces.schemas import InterfaceConfigResponse, InterfaceEntryRequest, InterfaceMutationResponse, InterfaceSectionResponse, InterfacesScanResponse, ModuleStatus
from modules.interfaces.service import delete_interface, get_section, patch_named_interface, read_candidate_config, scan_interfaces, update_interface

router = APIRouter(prefix="/interfaces", tags=["interfaces"])


@router.get("/status", response_model=ModuleStatus, summary="Interfaces status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que el módulo interfaces responde.

    Formato:
    ```text
    GET /api/v1/interfaces/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces/status
    ```
    """
    return {"status": "ok", "module": "interfaces", "user": user["user_name"]}


@router.get("", response_model=InterfaceConfigResponse, summary="List all interfaces")
def list_all_interfaces_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista todas las interfaces.

    Formato:
    ```text
    GET /api/v1/interfaces
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces
    ```
    """
    return {"config": read_candidate_config()}


@router.post("/scan", response_model=InterfacesScanResponse, summary="Scan interfaces")
def scan_interfaces_endpoint(user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza la detección de interfaces.

    Warning!
    Esta llamada se usa, para cuando se ha hecho un add o delete de interfaces en la maquina para que sea reconocida.
    Asegurate de que has hecho commit y no tienes ningun cambio por aplicar antes de ejecutar esta llamada.
    Pues sobreescribira la configuracion candidata con la que está actualmente running, cualquier cambio no comitado se perderá.
    No se recomienda su uso si estás trabajando directamente sobre interfaces fisicas en lugar de estar trabajando con interfaces bridges o vlans.

    Formato:
    ```text
    POST /api/v1/interfaces/scan
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/interfaces/scan
    ```
    """
    return scan_interfaces()


@router.get("/section/{section}", response_model=InterfaceSectionResponse, summary="List interface section")
def list_interface_section_endpoint(section: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista las interfaces de una sección.

    Formato:
    ```text
    GET /api/v1/interfaces/section/{section}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces/section/bridges
    ```
    """
    return get_section(section)


@router.get("/ethernets", response_model=InterfaceSectionResponse, summary="List ethernet interfaces")
def list_ethernets_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista interfaces físicas.

    Formato:
    ```text
    GET /api/v1/interfaces/ethernets
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces/ethernets
    ```
    """
    return get_section("ethernets")


@router.post("/ethernets", response_model=InterfaceMutationResponse, summary="Create ethernet interface")
def create_ethernet_endpoint(payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una interfaz física.

    Formato:
    ```text
    POST /api/v1/interfaces/ethernets
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/interfaces/ethernets
    ```

    Body:
    ```json
    {"config":{"name":"ens22"}}
    ```
    """
    return update_interface("ethernets", payload.config)


@router.patch("/ethernets/{uuid}", response_model=InterfaceMutationResponse, summary="Update ethernet interface")
def patch_ethernet_endpoint(uuid: str, payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una interfaz física.

    Formato:
    ```text
    PATCH /api/v1/interfaces/ethernets/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/interfaces/ethernets/ethernet-ens22-19700101000000000-0001
    ```

    Body:
    ```json
    {"config":{"dhcp4":"True"}}
    ```
    """
    return patch_named_interface("ethernets", uuid, payload.config)


@router.delete("/ethernets/{uuid}", response_model=InterfaceMutationResponse, summary="Delete ethernet interface")
def delete_ethernet_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una interfaz física.

    Formato:
    ```text
    DELETE /api/v1/interfaces/ethernets/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/interfaces/ethernets/ethernet-ens22-19700101000000000-0001
    ```
    """
    return delete_interface("ethernets", uuid)


@router.get("/bridges", response_model=InterfaceSectionResponse, summary="List bridge interfaces")
def list_bridges_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista interfaces bridge.

    Formato:
    ```text
    GET /api/v1/interfaces/bridges
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces/bridges
    ```
    """
    return get_section("bridges")


@router.post("/bridges", response_model=InterfaceMutationResponse, summary="Create bridge interface")
def create_bridge_endpoint(payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una interfaz bridge.

    Formato:
    ```text
    POST /api/v1/interfaces/bridges
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/interfaces/bridges
    ```

    Body:
    ```json
    {"config":{"name":"br10","interfaces":"ens19","addresses":"192.168.10.1/24"}}
    ```
    """
    return update_interface("bridges", payload.config)


@router.patch("/bridges/{uuid}", response_model=InterfaceMutationResponse, summary="Update bridge interface")
def patch_bridge_endpoint(uuid: str, payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una interfaz bridge.

    Formato:
    ```text
    PATCH /api/v1/interfaces/bridges/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/interfaces/bridges/bridge-br10-19700101000000000-0001
    ```

    Body:
    ```json
    {"config":{"addresses":"192.168.10.2/24"}}
    ```
    """
    return patch_named_interface("bridges", uuid, payload.config)


@router.delete("/bridges/{uuid}", response_model=InterfaceMutationResponse, summary="Delete bridge interface")
def delete_bridge_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una interfaz bridge.

    Formato:
    ```text
    DELETE /api/v1/interfaces/bridges/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/interfaces/bridges/bridge-br10-19700101000000000-0001
    ```
    """
    return delete_interface("bridges", uuid)


@router.get("/bonds", response_model=InterfaceSectionResponse, summary="List bond interfaces")
def list_bonds_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista interfaces bond.

    Formato:
    ```text
    GET /api/v1/interfaces/bonds
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces/bonds
    ```
    """
    return get_section("bonds")


@router.post("/bonds", response_model=InterfaceMutationResponse, summary="Create bond interface")
def create_bond_endpoint(payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una interfaz bond.

    Formato:
    ```text
    POST /api/v1/interfaces/bonds
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/interfaces/bonds
    ```

    Body:
    ```json
    {"config":{"interfaces":"ens20","parameters.mode":"active-backup"}}
    ```
    """
    return update_interface("bonds", payload.config)


@router.patch("/bonds/{uuid}", response_model=InterfaceMutationResponse, summary="Update bond interface")
def patch_bond_endpoint(uuid: str, payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una interfaz bond.

    Formato:
    ```text
    PATCH /api/v1/interfaces/bonds/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/interfaces/bonds/bond-bond0-19700101000000000-0001
    ```

    Body:
    ```json
    {"config":{"dhcp4":"False"}}
    ```
    """
    return patch_named_interface("bonds", uuid, payload.config)


@router.delete("/bonds/{uuid}", response_model=InterfaceMutationResponse, summary="Delete bond interface")
def delete_bond_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una interfaz bond.

    Formato:
    ```text
    DELETE /api/v1/interfaces/bonds/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/interfaces/bonds/bond-bond0-19700101000000000-0001
    ```
    """
    return delete_interface("bonds", uuid)


@router.get("/vlans", response_model=InterfaceSectionResponse, summary="List vlan interfaces")
def list_vlans_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista interfaces VLAN.

    Formato:
    ```text
    GET /api/v1/interfaces/vlans
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces/vlans
    ```
    """
    return get_section("vlans")


@router.post("/vlans", response_model=InterfaceMutationResponse, summary="Create vlan interface")
def create_vlan_endpoint(payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una interfaz VLAN.

    Formato:
    ```text
    POST /api/v1/interfaces/vlans
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/interfaces/vlans
    ```

    Body:
    ```json
    {"config":{"id":"123","link":"br0","addresses":"10.123.0.1/24"}}
    ```
    """
    return update_interface("vlans", payload.config)


@router.patch("/vlans/{uuid}", response_model=InterfaceMutationResponse, summary="Update vlan interface")
def patch_vlan_endpoint(uuid: str, payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una interfaz VLAN.

    Formato:
    ```text
    PATCH /api/v1/interfaces/vlans/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/interfaces/vlans/vlan-vlan123-19700101000000000-0001
    ```

    Body:
    ```json
    {"config":{"addresses":"10.123.0.2/24"}}
    ```
    """
    return patch_named_interface("vlans", uuid, payload.config)


@router.delete("/vlans/{uuid}", response_model=InterfaceMutationResponse, summary="Delete vlan interface")
def delete_vlan_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una interfaz VLAN.

    Formato:
    ```text
    DELETE /api/v1/interfaces/vlans/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/interfaces/vlans/vlan-vlan123-19700101000000000-0001
    ```
    """
    return delete_interface("vlans", uuid)


@router.get("/wifis", response_model=InterfaceSectionResponse, summary="List wifi interfaces")
def list_wifis_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista interfaces WiFi.

    Formato:
    ```text
    GET /api/v1/interfaces/wifis
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/interfaces/wifis
    ```
    """
    return get_section("wifis")


@router.post("/wifis", response_model=InterfaceMutationResponse, summary="Create wifi interface")
def create_wifi_endpoint(payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una interfaz WiFi.

    Formato:
    ```text
    POST /api/v1/interfaces/wifis
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/interfaces/wifis
    ```

    Body:
    ```json
    {"config":{"addresses":"192.168.50.1/24"}}
    ```
    """
    return update_interface("wifis", payload.config)


@router.patch("/wifis/{uuid}", response_model=InterfaceMutationResponse, summary="Update wifi interface")
def patch_wifi_endpoint(uuid: str, payload: InterfaceEntryRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una interfaz WiFi.

    Formato:
    ```text
    PATCH /api/v1/interfaces/wifis/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/interfaces/wifis/wifi-wlan0-19700101000000000-0001
    ```

    Body:
    ```json
    {"config":{"addresses":"192.168.50.2/24"}}
    ```
    """
    return patch_named_interface("wifis", uuid, payload.config)


@router.delete("/wifis/{uuid}", response_model=InterfaceMutationResponse, summary="Delete wifi interface")
def delete_wifi_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una interfaz WiFi.

    Formato:
    ```text
    DELETE /api/v1/interfaces/wifis/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/interfaces/wifis/wifi-wlan0-19700101000000000-0001
    ```
    """
    return delete_interface("wifis", uuid)
