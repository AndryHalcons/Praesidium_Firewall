"""Schemas BPFilter."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str


class BpfilterConfigResponse(BaseModel):
    config: dict[str, Any]


class BpfilterSectionResponse(BaseModel):
    hook: str
    rules: list[dict[str, Any]]


class BpfilterRuleRequest(BaseModel):
    rule: dict[str, Any] = Field(default_factory=dict)


class BpfilterMutationResponse(BaseModel):
    success: bool
    action: str
    hook: str | None = None
    id: str | None = None
