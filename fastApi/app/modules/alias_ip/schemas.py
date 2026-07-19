"""
Schemas Pydantic de Alias IP.
Alias IP Pydantic schemas.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AliasSection(StrEnum):
    alias_address = "alias_address"
    alias_addr_group = "alias_addr_group"


class AliasCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=29)
    content: list[str] = Field(default_factory=list)


class AliasUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=29)
    content: list[str] | None = None


class AliasPublic(BaseModel):
    id: str
    UUID: str
    name: str
    content: list[str]


class AliasListResponse(BaseModel):
    section: AliasSection
    aliases: list[AliasPublic]


class AliasTranslateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    UUID: str = Field(min_length=1)


class AliasTranslateResponse(BaseModel):
    UUID: str
    section: AliasSection
    name: str


class AliasDeepTranslateResponse(BaseModel):
    UUID: str
    section: AliasSection
    name: str
    content: list[str] | None = None
    content_names: list[str] | None = None
    deep_content: list[str]


class AliasDeepTranslateSanitizedResponse(AliasDeepTranslateResponse):
    deep_content_sanitized: list[str]


class AliasStatus(BaseModel):
    status: str
    module: str
    extra: dict[str, Any] | None = None
