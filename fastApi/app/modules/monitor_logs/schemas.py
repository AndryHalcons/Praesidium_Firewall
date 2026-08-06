"""Schemas Pydantic del módulo Monitor Logs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    """Estado mínimo del módulo."""

    status: str
    module: str
    user: str | None = None


class MonitorLogSearchRequest(BaseModel):
    """Filtros de búsqueda de logs."""

    Start_Date: str = Field(default="")
    Start_Time: str = Field(default="")
    End_Date: str = Field(default="")
    End_Time: str = Field(default="")
    Source_IP: str = Field(default="")
    Destination_IP: str = Field(default="")
    Source_Port: str = Field(default="")
    Destination_Port: str = Field(default="")
    Protocol: str = Field(default="")
    Action: str = Field(default="")
    Firewall: str = Field(default="")
    Max_Records: str = Field(default="100")


class MonitorLogSearchResponse(BaseModel):
    """Resultado de búsqueda de logs."""

    logs: Any


class MonitorLogOptionsResponse(BaseModel):
    """Opciones soportadas por Monitor Logs."""

    options: dict[str, Any]
