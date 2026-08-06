"""
Router HTTP del módulo Users.
HTTP router for the Users module.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from core.security.dependencies import current_active_user, require_admin
from modules.users.schemas import PasswordChangeRequest, UserCreate, UserPublic, UserUpdate, UsersListResponse
from modules.users.service import change_user_password, create_user, delete_user, list_public_users, update_user


router = APIRouter(prefix="/users", tags=["users"])


@router.get("/status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba router protegido. / Check protected router."""
    return {"status": "ok", "module": "users", "user": user["user_name"]}


@router.get("/", response_model=UsersListResponse)
def list_users_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, object]:
    """Lista usuarios candidate para viewer/admin. / List candidate users for viewer/admin."""
    return {"users": list_public_users()}


@router.post("/", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def create_user_endpoint(payload: UserCreate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, str]:
    """Crea usuario en candidate. / Create user in candidate."""
    return create_user(payload)


@router.patch("/{user_uuid}", response_model=UserPublic)
def update_user_endpoint(user_uuid: str, payload: UserUpdate, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, str]:
    """Edita usuario en candidate sin permitir UUID/password_changed_at."""
    return update_user(user_uuid, payload)


@router.post("/{user_uuid}/password", response_model=UserPublic)
def change_user_password_endpoint(user_uuid: str, payload: PasswordChangeRequest, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, str]:
    """Cambia contraseña y password_changed_at internamente."""
    return change_user_password(user_uuid, payload, user["user_name"])


@router.delete("/{user_uuid}")
def delete_user_endpoint(user_uuid: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, str]:
    """Borra el objeto usuario completo por UUID. / Delete full user object by UUID."""
    return delete_user(user_uuid)
