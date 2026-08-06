"""Schemas del módulo System Logging."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr


class StrictSchema(BaseModel):
    """Schema estricto sin campos ajenos."""

    model_config = ConfigDict(extra="forbid")


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str | None = None


class JournaldConfig(StrictSchema):
    uuid: StrictStr
    system_max_use: StrictStr
    system_keep_free: StrictStr
    runtime_max_use: StrictStr
    max_retention_sec: StrictStr
    compress: StrictBool


class JournaldUpdate(StrictSchema):
    system_max_use: StrictStr | None = None
    system_keep_free: StrictStr | None = None
    runtime_max_use: StrictStr | None = None
    max_retention_sec: StrictStr | None = None
    compress: StrictBool | None = None


class SystemLogsConfig(StrictSchema):
    uuid: StrictStr
    enabled: StrictBool
    rotation: StrictStr
    rotate: StrictInt
    maxsize: StrictStr
    compress: StrictBool
    delaycompress: StrictBool


class SystemLogsUpdate(StrictSchema):
    enabled: StrictBool | None = None
    rotation: StrictStr | None = None
    rotate: StrictInt | None = None
    maxsize: StrictStr | None = None
    compress: StrictBool | None = None
    delaycompress: StrictBool | None = None


class NftablesLogsConfig(StrictSchema):
    uuid: StrictStr
    enabled: StrictBool
    size: StrictStr
    rotate: StrictInt
    compress: StrictBool
    delaycompress: StrictBool


class NftablesLogsUpdate(StrictSchema):
    enabled: StrictBool | None = None
    size: StrictStr | None = None
    rotate: StrictInt | None = None
    compress: StrictBool | None = None
    delaycompress: StrictBool | None = None


class SystemLoggingConfig(StrictSchema):
    journald: JournaldConfig
    system_logs: SystemLogsConfig
    nftables_logs: NftablesLogsConfig


class SystemLoggingConfigResponse(BaseModel):
    config: SystemLoggingConfig


class JournaldResponse(BaseModel):
    journald: JournaldConfig


class SystemLogsResponse(BaseModel):
    system_logs: SystemLogsConfig


class NftablesLogsResponse(BaseModel):
    nftables_logs: NftablesLogsConfig


class MutationResponse(BaseModel):
    success: bool = True
    section: str
