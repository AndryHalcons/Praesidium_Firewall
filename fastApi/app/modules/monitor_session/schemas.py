"""Schemas Pydantic del módulo Monitor Session."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    """Estado mínimo del módulo."""

    status: str
    module: str
    user: str | None = None


class SessionRow(BaseModel):
    """Fila conntrack normalizada."""

    proto: str
    state: str
    source: str
    source_port: str
    destination: str
    destination_port: str
    reply_source: str
    reply_source_port: str
    reply_destination: str
    reply_destination_port: str
    timeout: str
    assured: str
    id: str


class SessionCommandRequest(BaseModel):
    """Petición controlada para ejecutar una acción conntrack."""

    action: str = Field(..., description="Conntrack action: -L, -E, -C, -S, -D, -F")
    arguments: str | list[str] | None = Field(default=None, description="Optional conntrack arguments")


class SessionListResponse(BaseModel):
    """Listado de sesiones."""

    rows: list[SessionRow]
    has_snapshot: bool


class SessionRefreshResponse(BaseModel):
    """Resultado de refresh/listado clásico."""

    status: str
    message: str
    output: str
    rows: list[SessionRow]


class SessionCommandResponse(BaseModel):
    """Resultado genérico de una acción conntrack controlada."""

    status: str
    action: str
    arguments: list[str]
    output: str
    return_code: int
    rows: list[SessionRow] = []
    has_snapshot: bool = False


class SessionColumnsResponse(BaseModel):
    """Columnas visibles."""

    columns: list[str]
