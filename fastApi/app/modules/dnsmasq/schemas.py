"""Schemas Pydantic del módulo Dnsmasq."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    """Estado mínimo del módulo. / Minimal module status."""

    status: str
    module: str
    user: str | None = None


class DnsmasqRuleRequest(BaseModel):
    """Payload de regla dnsmasq. / Dnsmasq rule payload."""

    rule: dict[str, Any] = Field(...)


class DnsmasqConfigResponse(BaseModel):
    """Respuesta de configuración completa. / Full configuration response."""

    config: dict[str, Any]


class DnsmasqSectionResponse(BaseModel):
    """Respuesta de sección dnsmasq. / Dnsmasq section response."""

    section: str
    rules: list[dict[str, Any]]


class DnsmasqInterfacesResponse(BaseModel):
    """Respuesta de interfaces permitidas. / Allowed interfaces response."""

    interfaces: list[str]
    items: list[str]


class DnsmasqMutationResponse(BaseModel):
    """Respuesta de mutación dnsmasq. / Dnsmasq mutation response."""

    success: bool
    action: str
    section: str
    id: str | None = None
    uuid: str | None = None
    updated: str | None = None
    deleted_id: str | None = None
