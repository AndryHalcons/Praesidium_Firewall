"""Schemas Pydantic del módulo Dashboard."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str


class CpuStats(BaseModel):
    average: float = Field(ge=0, le=100)
    cores: list[float]
    core_count: int = Field(ge=0)


class RamStats(BaseModel):
    total: int = Field(ge=0)
    used: int = Field(ge=0)
    free: int = Field(ge=0)
    cached: int = Field(ge=0)
    used_percent: float = Field(ge=0, le=100)


class DiskMount(BaseModel):
    mountpoint: str
    source: str
    fstype: str
    total: int = Field(ge=0)
    used: int = Field(ge=0)
    available: int = Field(ge=0)
    used_percent: float = Field(ge=0, le=100)
    status: str


class DiskSummary(BaseModel):
    total: int = Field(ge=0)
    used: int = Field(ge=0)
    available: int = Field(ge=0)
    used_percent: float = Field(ge=0, le=100)
    device_count: int = Field(ge=0)


class DiskStats(BaseModel):
    summary: DiskSummary
    mounts: list[DiskMount]


class NetworkInterface(BaseModel):
    name: str
    rx_bytes: int = Field(ge=0)
    tx_bytes: int = Field(ge=0)
    rx_bytes_per_second: float = Field(ge=0)
    tx_bytes_per_second: float = Field(ge=0)


class NetworkStats(BaseModel):
    interfaces: list[NetworkInterface]


class DashboardStatsResponse(BaseModel):
    status: str
    timestamp: float
    load_average: list[float]
    uptime_seconds: float = Field(ge=0)
    cpu: CpuStats
    ram: RamStats
    disk: DiskStats
    network: NetworkStats
    errors: list[dict[str, Any]] = []
