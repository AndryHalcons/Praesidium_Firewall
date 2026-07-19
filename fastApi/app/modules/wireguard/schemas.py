"""Schemas Pydantic del módulo WireGuard."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    """Estado mínimo del módulo. / Minimal module status."""

    status: str
    module: str
    user: str | None = None


class WireGuardRuleRequest(BaseModel):
    """Payload de regla WireGuard. / WireGuard rule payload."""

    rule: dict[str, Any] = Field(...)


class WireGuardConfigResponse(BaseModel):
    """Respuesta de configuración WireGuard."""

    config: dict[str, Any]


class WireGuardSectionResponse(BaseModel):
    """Respuesta de sección WireGuard."""

    section: str
    entries: dict[str, dict[str, Any]]


class WireGuardEntryResponse(BaseModel):
    """Respuesta de entrada WireGuard."""

    section: str
    name: str
    entry: dict[str, Any]


class WireGuardMutationResponse(BaseModel):
    """Respuesta de mutación WireGuard."""

    success: bool
    action: str
    section: str
    id: str | None = None
    UUID: str | None = None
    name: str | None = None
    updated: str | None = None
    deleted: str | None = None
