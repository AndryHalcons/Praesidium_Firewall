"""
Schemas del módulo Interfaces.
Interfaces module schemas.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str | None = None


class InterfaceConfigResponse(BaseModel):
    config: dict[str, Any]


class InterfaceSectionResponse(BaseModel):
    section: str
    entries: dict[str, Any]


class InterfaceRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule: dict[str, Any] = Field(default_factory=dict)


class InterfaceEntryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config: dict[str, Any] = Field(default_factory=dict)


class InterfaceMutationResponse(BaseModel):
    success: bool
    section: str
    name: str
    uuid: str | None = None
    action: str


class InterfacesScanResponse(BaseModel):
    success: bool
    action: str
    script: str
    stdout: str = ""
    stderr: str = ""

