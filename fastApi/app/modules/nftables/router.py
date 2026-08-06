"""Router HTTP del módulo Nftables."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from core.security.dependencies import current_active_user, require_admin
from modules.nftables.schemas import NftablesChainRequest, NftablesChainsResponse, NftablesChainResponse, NftablesConfigResponse, NftablesMutationResponse, NftablesRuleRequest, NftablesTableChainResponse, NftablesTableChainsResponse, NftablesTableRequest, NftablesTableResponse, NftablesTablesResponse, ModuleStatus
from modules.nftables.service import available_chains, create_chain, create_table, delete_chain, delete_rule, delete_table, get_chain, get_table, list_rules_for_chain, list_table_chains, list_tables, read_candidate_config, update_existing_rule, upsert_rule

router = APIRouter(prefix="/nftables", tags=["nftables"])


@router.get("/status", response_model=ModuleStatus, summary="Nftables status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que el módulo Nftables responde.

    Formato:
    ```text
    GET /api/v1/nftables/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables/status
    ```
    """
    return {"status": "ok", "module": "nftables", "user": user["user_name"]}


@router.get("/chains", response_model=NftablesChainsResponse, summary="List Nftables chains")
def list_chains_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista las combinaciones table/chain disponibles.

    Formato:
    ```text
    GET /api/v1/nftables/chains
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables/chains
    ```
    """
    return {"chains": available_chains()}




@router.get("/tables", response_model=NftablesTablesResponse, summary="List Nftables tables")
def list_tables_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista tablas Nftables.

    Formato:
    ```text
    GET /api/v1/nftables/tables
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables/tables
    ```
    """
    return {"tables": list_tables()}


@router.post("/tables", response_model=NftablesMutationResponse, summary="Create Nftables table")
def create_table_endpoint(payload: NftablesTableRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una tabla Nftables inet.

    Formato:
    ```text
    POST /api/v1/nftables/tables
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/nftables/tables
    ```

    Body:
    ```json
    {"table":{"name":"custom_filter","family":"inet"}}
    ```
    """
    return create_table(payload.table)


@router.get("/tables/{table}/chains", response_model=NftablesTableChainsResponse, summary="List Nftables table chains")
def list_table_chains_endpoint(table: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista chains de una tabla Nftables.

    Formato:
    ```text
    GET /api/v1/nftables/tables/{table}/chains
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables/tables/filter/chains
    ```
    """
    return {"table": table, "chains": list_table_chains(table)}


@router.post("/tables/{table}/chains", response_model=NftablesMutationResponse, summary="Create Nftables chain")
def create_chain_endpoint(table: str, payload: NftablesChainRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea una chain Nftables inet.

    Formato:
    ```text
    POST /api/v1/nftables/tables/{table}/chains
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/nftables/tables/filter/chains
    ```

    Body:
    ```json
    {"chain":{"name":"CUSTOM_CHAIN","type":"filter","hook":"","policy":"accept"}}
    ```
    """
    return create_chain(table, payload.chain)


@router.get("/tables/{table}/chains/{chain}", response_model=NftablesTableChainResponse, summary="Get Nftables chain")
def get_chain_endpoint(table: str, chain: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta una chain Nftables.

    Formato:
    ```text
    GET /api/v1/nftables/tables/{table}/chains/{chain}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables/tables/filter/chains/input
    ```
    """
    return {"table": table, "chain": get_chain(table, chain)}


@router.delete("/tables/{table}/chains/{chain}", response_model=NftablesMutationResponse, summary="Delete Nftables chain")
def delete_chain_endpoint(table: str, chain: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una chain Nftables.

    Formato:
    ```text
    DELETE /api/v1/nftables/tables/{table}/chains/{chain}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/nftables/tables/filter/chains/CUSTOM_CHAIN
    ```
    """
    return delete_chain(table, chain)


@router.get("/tables/{table}", response_model=NftablesTableResponse, summary="Get Nftables table")
def get_table_endpoint(table: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta una tabla Nftables.

    Formato:
    ```text
    GET /api/v1/nftables/tables/{table}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables/tables/filter
    ```
    """
    return {"table": get_table(table)}


@router.delete("/tables/{table}", response_model=NftablesMutationResponse, summary="Delete Nftables table")
def delete_table_endpoint(table: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una tabla Nftables.

    Formato:
    ```text
    DELETE /api/v1/nftables/tables/{table}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/nftables/tables/custom_filter
    ```
    """
    return delete_table(table)


@router.get("", response_model=NftablesConfigResponse, summary="List Nftables rules")
def list_all_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista todas las reglas Nftables.

    Formato:
    ```text
    GET /api/v1/nftables
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables
    ```
    """
    return {"config": read_candidate_config()}


@router.get("/{table}/{chain}", response_model=NftablesChainResponse, summary="List Nftables chain rules")
def list_chain_endpoint(table: str, chain: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista reglas de una table/chain Nftables.

    Formato:
    ```text
    GET /api/v1/nftables/{table}/{chain}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/nftables/filter/FORWARDING
    ```
    """
    return {"chain": chain, "rules": list_rules_for_chain(table, chain)}


@router.post("/{table}/{chain}", response_model=NftablesMutationResponse, summary="Create Nftables rule")
def create_rule_endpoint(table: str, chain: str, payload: NftablesRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Crea o actualiza una regla Nftables.

    Formato:
    ```text
    POST /api/v1/nftables/{table}/{chain}
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/nftables/filter/FORWARDING
    ```

    Body:
    ```json
    {"rule":{"action":"accept","enable":"true","ip.protocol":"tcp","dport":"443"}}
    ```
    """
    return upsert_rule(table, chain, payload.rule)


@router.patch("/{table}/{chain}/{rule_id}", response_model=NftablesMutationResponse, summary="Update Nftables rule")
def update_rule_endpoint(table: str, chain: str, rule_id: str, payload: NftablesRuleRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Actualiza una regla Nftables.

    Formato:
    ```text
    PATCH /api/v1/nftables/{table}/{chain}/{rule_id}
    ```

    Ejemplo de uso:
    ```text
    PATCH http://192.0.2.10:8000/api/v1/nftables/filter/FORWARDING/5
    ```

    Body:
    ```json
    {"rule":{"action":"drop","enable":"true","ip.protocol":"tcp"}}
    ```
    """
    return update_existing_rule(table, chain, rule_id, payload.rule)


@router.delete("/{table}/{chain}/{rule_id}", response_model=NftablesMutationResponse, summary="Delete Nftables rule")
def delete_rule_endpoint(table: str, chain: str, rule_id: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra una regla Nftables.

    Formato:
    ```text
    DELETE /api/v1/nftables/{table}/{chain}/{rule_id}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/nftables/filter/FORWARDING/5
    ```
    """
    return delete_rule(table, chain, rule_id)
