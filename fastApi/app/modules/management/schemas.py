"""Schemas Pydantic del módulo Management."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str | None = None


class ManagementConfigResponse(BaseModel):
    config: dict[str, Any]


class ListenerRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    listen_ip: str
    listen_port: str
    server_name: str = "praesidium.local"


class ListenerResponse(BaseModel):
    listener: dict[str, Any]


class TlsRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    certificate_file: str
    certificate_key: str
    certificate_chain: str


class TlsResponse(BaseModel):
    tls: dict[str, Any]


class AllowedSourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_cidr: str
    description: str = ""


class AllowedSourceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_cidr: str | None = None
    description: str | None = None


class AllowedSourcesResponse(BaseModel):
    allowed_sources: list[dict[str, Any]]


class AllowedSourceResponse(BaseModel):
    allowed_source: dict[str, Any]


class MutationResponse(BaseModel):
    success: bool = True
    section: str
    id: str | None = None
