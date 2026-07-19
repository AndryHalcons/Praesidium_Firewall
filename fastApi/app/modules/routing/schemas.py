"""Schemas del módulo Routing."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str


class RoutingDataResponse(BaseModel):
    routes: list[dict[str, Any]] = Field(default_factory=list)
    rules: list[dict[str, Any]] = Field(default_factory=list)
    has_snapshot: bool = False


class RoutingReloadResponse(BaseModel):
    status: str
    routes: list[dict[str, Any]] = Field(default_factory=list)
    rules: list[dict[str, Any]] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
