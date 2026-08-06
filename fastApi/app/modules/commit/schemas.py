"""Schemas Pydantic del módulo Commit."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str | None = None


class CommitUserResponse(BaseModel):
    commit: dict[str, str]


class CommitPreviewResponse(BaseModel):
    success: bool
    summary: dict[str, int]
    changes: list[dict[str, Any]]


class CommitConfigResponse(BaseModel):
    mode: str
    content: str


class CommitApplyResponse(BaseModel):
    commit_result: dict[str, Any]
    message: str | None = None
    commit_details: Any = None
