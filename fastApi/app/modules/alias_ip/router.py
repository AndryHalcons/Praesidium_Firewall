"""
Router HTTP de Alias IP.
Alias IP HTTP router.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from core.security.dependencies import current_active_user, require_admin
from modules.alias_ip.schemas import AliasCreate, AliasDeepTranslateResponse, AliasDeepTranslateSanitizedResponse, AliasListResponse, AliasPublic, AliasTranslateRequest, AliasTranslateResponse, AliasUpdate
from modules.alias_ip.service import create_alias, deep_translate_alias, deep_translate_sanitized_alias, delete_alias, get_alias, list_aliases, translate_alias, update_alias

router = APIRouter(prefix="/alias-ip", tags=["alias-ip"])


@router.get("/status")
# Endpoint protegido para comprobar que el módulo responde.
# Protected endpoint to check that the module responds.
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    return {"status": "ok", "module": "alias_ip", "user": user["user_name"]}


@router.post("/translate", response_model=AliasTranslateResponse)
# Endpoint UUID -> nombre visible.
# Endpoint for UUID -> visible name.
def translate_alias_endpoint(payload: AliasTranslateRequest, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    return translate_alias(payload.UUID)


@router.post("/deep_translate", response_model=AliasDeepTranslateResponse, response_model_exclude_none=True)
# Endpoint UUID -> contenido final recursivo.
# Endpoint for UUID -> recursive final content.
def deep_translate_alias_endpoint(payload: AliasTranslateRequest, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    return deep_translate_alias(payload.UUID)


@router.post("/deep_translate_sanitized", response_model=AliasDeepTranslateSanitizedResponse, response_model_exclude_none=True)
# Endpoint UUID -> contenido final recursivo saneado.
# Endpoint for UUID -> sanitized recursive final content.
def deep_translate_sanitized_alias_endpoint(payload: AliasTranslateRequest, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    return deep_translate_sanitized_alias(payload.UUID)


@router.get("/addresses", response_model=AliasListResponse)
# Endpoint que lista alias simples de la familia.
# Endpoint that lists simple aliases for the family.
def list_simple_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    return {"section": "alias_address", "aliases": list_aliases("alias_address")}


@router.post("/addresses", response_model=AliasPublic, status_code=status.HTTP_201_CREATED)
# Endpoint admin para crear alias simples.
# Admin endpoint to create simple aliases.
def create_simple_endpoint(payload: AliasCreate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    return create_alias("alias_address", payload)


@router.get("/addresses/{uuid}", response_model=AliasPublic)
# Endpoint que lee un alias simple por UUID.
# Endpoint that reads one simple alias by UUID.
def get_simple_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    return get_alias("alias_address", uuid)


@router.patch("/addresses/{uuid}", response_model=AliasPublic)
# Endpoint admin para actualizar alias simples.
# Admin endpoint to update simple aliases.
def update_simple_endpoint(uuid: str, payload: AliasUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    return update_alias("alias_address", uuid, payload)


@router.delete("/addresses/{uuid}")
# Endpoint admin para borrar alias simples.
# Admin endpoint to delete simple aliases.
def delete_simple_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, str]:
    return delete_alias("alias_address", uuid)


@router.get("/address-groups", response_model=AliasListResponse)
# Endpoint que lista grupos de la familia.
# Endpoint that lists groups for the family.
def list_group_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    return {"section": "alias_addr_group", "aliases": list_aliases("alias_addr_group")}


@router.post("/address-groups", response_model=AliasPublic, status_code=status.HTTP_201_CREATED)
# Endpoint admin para crear grupos.
# Admin endpoint to create groups.
def create_group_endpoint(payload: AliasCreate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    return create_alias("alias_addr_group", payload)


@router.get("/address-groups/{uuid}", response_model=AliasPublic)
# Endpoint que lee un grupo por UUID.
# Endpoint that reads one group by UUID.
def get_group_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    return get_alias("alias_addr_group", uuid)


@router.patch("/address-groups/{uuid}", response_model=AliasPublic)
# Endpoint admin para actualizar grupos.
# Admin endpoint to update groups.
def update_group_endpoint(uuid: str, payload: AliasUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, object]:
    return update_alias("alias_addr_group", uuid, payload)


@router.delete("/address-groups/{uuid}")
# Endpoint admin para borrar grupos.
# Admin endpoint to delete groups.
def delete_group_endpoint(uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, str]:
    return delete_alias("alias_addr_group", uuid)
