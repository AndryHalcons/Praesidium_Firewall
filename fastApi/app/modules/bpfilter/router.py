"""Router HTTP del módulo BPFilter."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.bpfilter.schemas import BpfilterConfigResponse, BpfilterMutationResponse, BpfilterRuleRequest, BpfilterSectionResponse, ModuleStatus
from modules.bpfilter.service import available_hooks, delete_rule, list_rules_for_hook, read_candidate_config, upsert_rule

router = APIRouter(prefix="/bpfilter", tags=["bpfilter"])


@router.get("/status", response_model=ModuleStatus, summary="BPFilter status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que el módulo BPFilter responde.

    Formato:
    ```text
    GET /api/v1/bpfilter/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/bpfilter/status
    ```
    """
    return {"status": "ok", "module": "bpfilter", "user": user["user_name"]}


@router.get("/hooks", summary="List BPFilter hooks")
def list_hooks_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista los hooks BPFilter disponibles.

    Formato:
    ```text
    GET /api/v1/bpfilter/hooks
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/bpfilter/hooks
    ```
    """
    return {"hooks": available_hooks()}


@router.get("", response_model=BpfilterConfigResponse, summary="List BPFilter rules")
def list_all_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista todas las reglas BPFilter.

    Formato:
    ```text
    GET /api/v1/bpfilter
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/bpfilter
    ```
    """
    return {"config": read_candidate_config()}


@router.get("/{hook}", response_model=BpfilterSectionResponse, summary="List BPFilter hook rules")
def list_hook_endpoint(hook: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista reglas de un hook BPFilter.

    Formato:
    ```text
    GET /api/v1/bpfilter/{hook}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/bpfilter/xdp
    ```
    """
    return {"hook": hook, "rules": list_rules_for_hook(hook)}


@router.post("/{hook}", response_model=BpfilterMutationResponse, summary="Create BPFilter rule")
def create_rule_endpoint(hook: str, payload: BpfilterRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea o actualiza una regla BPFilter.

    Formato:
    ```text
    POST /api/v1/bpfilter/{hook}
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/bpfilter/xdp
    ```

    Body:
    ```json
    {"rule":{"interface":"br0","action":"DROP","enable":"true","l3_protocol":"IPv4","l4_protocol":"TCP"}}
    ```
    """
    return upsert_rule(hook, payload.rule)


@router.patch("/{hook}/{rule_id}", response_model=BpfilterMutationResponse, summary="Update BPFilter rule")
def update_rule_endpoint(hook: str, rule_id: str, payload: BpfilterRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una regla BPFilter.

    Formato:
    ```text
    PATCH /api/v1/bpfilter/{hook}/{rule_id}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/bpfilter/xdp/1
    ```

    Body:
    ```json
    {"rule":{"interface":"br0","action":"DROP","enable":"true","l3_protocol":"IPv4","l4_protocol":"TCP"}}
    ```
    """
    body = dict(payload.rule)
    body["id"] = rule_id
    return upsert_rule(hook, body)


@router.delete("/{hook}/{rule_id}", response_model=BpfilterMutationResponse, summary="Delete BPFilter rule")
def delete_rule_endpoint(hook: str, rule_id: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una regla BPFilter.

    Formato:
    ```text
    DELETE /api/v1/bpfilter/{hook}/{rule_id}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/bpfilter/xdp/1
    ```
    """
    return delete_rule(hook, rule_id)
