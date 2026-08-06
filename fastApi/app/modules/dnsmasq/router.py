"""Router HTTP del módulo Dnsmasq."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.dnsmasq.schemas import DnsmasqConfigResponse, DnsmasqInterfacesResponse, DnsmasqMutationResponse, DnsmasqRuleRequest, DnsmasqSectionResponse, ModuleStatus
from modules.dnsmasq.service import candidate_interfaces, create_reservation, create_scope, delete_reservation, delete_scope, get_reservation, get_scope, list_reservations, list_scopes, read_frontend_config, reservation_interfaces, update_reservation, update_scope

router = APIRouter(prefix="/dnsmasq", tags=["dnsmasq"])


@router.get("/status", response_model=ModuleStatus, summary="Dnsmasq status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que el módulo Dnsmasq responde.

    Formato:
    ```text
    GET /api/v1/dnsmasq/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq/status
    ```
    """
    return {"status": "ok", "module": "dnsmasq", "user": user["user_name"]}


@router.get("", response_model=DnsmasqConfigResponse, summary="List Dnsmasq config")
def list_config_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista la configuración Dnsmasq candidata.

    Formato:
    ```text
    GET /api/v1/dnsmasq
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq
    ```
    """
    return {"config": read_frontend_config()}


@router.get("/interfaces", response_model=DnsmasqInterfacesResponse, summary="List Dnsmasq interfaces")
def list_interfaces_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, list[str]]:
    """Lista interfaces candidatas válidas para Dnsmasq.

    Formato:
    ```text
    GET /api/v1/dnsmasq/interfaces
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq/interfaces
    ```
    """
    interfaces = candidate_interfaces()
    return {"interfaces": interfaces, "items": interfaces}


@router.get("/reservation-interfaces", response_model=DnsmasqInterfacesResponse, summary="List reservation interfaces")
def list_reservation_interfaces_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, list[str]]:
    """Lista interfaces con scope server activo.

    Formato:
    ```text
    GET /api/v1/dnsmasq/reservation-interfaces
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq/reservation-interfaces
    ```
    """
    interfaces = reservation_interfaces()
    return {"interfaces": interfaces, "items": interfaces}


@router.get("/scopes", response_model=DnsmasqSectionResponse, summary="List DHCP scopes")
def list_scopes_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista scopes DHCP/relay.

    Formato:
    ```text
    GET /api/v1/dnsmasq/scopes
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq/scopes
    ```
    """
    return {"section": "dhcp", "rules": list_scopes()}


@router.get("/scopes/{uuid}", summary="Get DHCP scope")
def get_scope_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta un scope DHCP/relay.

    Formato:
    ```text
    GET /api/v1/dnsmasq/scopes/{uuid}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq/scopes/scopes-1-example
    ```
    """
    return {"section": "dhcp", "rule": get_scope(uuid)}


@router.post("/scopes", response_model=DnsmasqMutationResponse, summary="Create DHCP scope")
def create_scope_endpoint(payload: DnsmasqRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea un scope DHCP/relay.

    Formato:
    ```text
    POST /api/v1/dnsmasq/scopes
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/dnsmasq/scopes
    ```

    Body:
    ```json
    {"rule":{"mode":"server","interface":"br1","range_start":"10.0.0.100","range_end":"10.0.0.200","gateway":"10.0.0.1","netmask":"255.255.255.0"}}
    ```
    """
    return create_scope(payload.rule)


@router.patch("/scopes/{uuid}", response_model=DnsmasqMutationResponse, summary="Update DHCP scope")
def update_scope_endpoint(uuid: str, payload: DnsmasqRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza un scope DHCP/relay.

    Formato:
    ```text
    PATCH /api/v1/dnsmasq/scopes/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/dnsmasq/scopes/scopes-1-example
    ```
    """
    return update_scope(uuid, payload.rule)


@router.delete("/scopes/{uuid}", response_model=DnsmasqMutationResponse, summary="Delete DHCP scope")
def delete_scope_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra un scope DHCP/relay.

    Formato:
    ```text
    DELETE /api/v1/dnsmasq/scopes/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/dnsmasq/scopes/scopes-1-example
    ```
    """
    return delete_scope(uuid)


@router.get("/reservations", response_model=DnsmasqSectionResponse, summary="List DHCP reservations")
def list_reservations_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista reservas DHCP.

    Formato:
    ```text
    GET /api/v1/dnsmasq/reservations
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq/reservations
    ```
    """
    return {"section": "dhcp_reservation", "rules": list_reservations()}


@router.get("/reservations/{uuid}", summary="Get DHCP reservation")
def get_reservation_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta una reserva DHCP.

    Formato:
    ```text
    GET /api/v1/dnsmasq/reservations/{uuid}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/dnsmasq/reservations/dhcpres-1-example
    ```
    """
    return {"section": "dhcp_reservation", "rule": get_reservation(uuid)}


@router.post("/reservations", response_model=DnsmasqMutationResponse, summary="Create DHCP reservation")
def create_reservation_endpoint(payload: DnsmasqRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una reserva DHCP.

    Formato:
    ```text
    POST /api/v1/dnsmasq/reservations
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/dnsmasq/reservations
    ```

    Body:
    ```json
    {"rule":{"interface":"br1","mac":"02:11:22:33:44:55","ip":"10.0.0.10"}}
    ```
    """
    return create_reservation(payload.rule)


@router.patch("/reservations/{uuid}", response_model=DnsmasqMutationResponse, summary="Update DHCP reservation")
def update_reservation_endpoint(uuid: str, payload: DnsmasqRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una reserva DHCP.

    Formato:
    ```text
    PATCH /api/v1/dnsmasq/reservations/{uuid}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/dnsmasq/reservations/dhcpres-1-example
    ```
    """
    return update_reservation(uuid, payload.rule)


@router.delete("/reservations/{uuid}", response_model=DnsmasqMutationResponse, summary="Delete DHCP reservation")
def delete_reservation_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una reserva DHCP.

    Formato:
    ```text
    DELETE /api/v1/dnsmasq/reservations/{uuid}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/dnsmasq/reservations/dhcpres-1-example
    ```
    """
    return delete_reservation(uuid)
