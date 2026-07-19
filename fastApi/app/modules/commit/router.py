"""Router HTTP del módulo Commit."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from core.security.dependencies import current_active_user, require_admin
from modules.commit.schemas import CommitApplyResponse, CommitConfigResponse, CommitPreviewResponse, CommitUserResponse, ModuleStatus
from modules.commit.service import apply_commit, commit_user, config_view, preview

router = APIRouter(prefix="/commit", tags=["commit"])


@router.get("/status", response_model=ModuleStatus, summary="Commit status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    return {"status": "ok", "module": "commit", "user": user["user_name"]}


@router.get("/user", response_model=CommitUserResponse, summary="Get commit user/date")
def user_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, dict[str, str]]:
    return commit_user(user["user_name"])


@router.get("/preview", response_model=CommitPreviewResponse, summary="Preview pending candidate/running changes")
def preview_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict:
    return preview()


@router.get("/config", response_model=CommitConfigResponse, summary="Safe config viewer")
def config_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)], mode: str = Query(..., pattern="^(candidate|running)$")) -> dict[str, str]:
    return config_view(mode)


@router.post("/apply", response_model=CommitApplyResponse, summary="Apply commit")
def apply_endpoint(user: Annotated[dict[str, str], Depends(require_admin)]) -> dict:
    return apply_commit(user["user_name"])
