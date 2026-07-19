"""Schemas Pydantic del módulo Services."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    """Estado mínimo del módulo."""

    status: str
    module: str
    user: str | None = None


class ServiceUpdateRequest(BaseModel):
    """Payload para actualizar desired_enabled."""

    desired_enabled: str = Field(...)


class ServicesConfigResponse(BaseModel):
    """Respuesta de configuración Services."""

    config: dict[str, Any]


class ServicesCatalogResponse(BaseModel):
    """Respuesta de catálogo fijo."""

    catalog: dict[str, dict[str, Any]]


class ServicesRowsResponse(BaseModel):
    """Respuesta de filas enriquecidas."""

    services: list[dict[str, Any]]


class ServiceEntryResponse(BaseModel):
    """Respuesta de servicio individual."""

    service_name: str
    service: dict[str, Any]


class ServicesRuntimeResponse(BaseModel):
    """Respuesta de runtime status."""

    services: dict[str, dict[str, str]]


class ServiceMutationResponse(BaseModel):
    """Respuesta de mutación Services."""

    success: bool
    service_name: str
    desired_enabled: str
