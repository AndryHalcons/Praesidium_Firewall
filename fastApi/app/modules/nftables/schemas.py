"""Schemas del módulo Nftables."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    status: str
    module: str
    user: str


class NftablesConfigResponse(BaseModel):
    config: dict[str, Any]


class NftablesChainResponse(BaseModel):
    chain: str
    rules: list[dict[str, Any]]


class NftablesChainsResponse(BaseModel):
    chains: list[dict[str, str]]


class NftablesRuleRequest(BaseModel):
    rule: dict[str, Any] = Field(default_factory=dict)


class NftablesMutationResponse(BaseModel):
    success: bool
    action: str
    table: str | None = None
    chain: str | None = None
    id: str | None = None



class NftablesTableRequest(BaseModel):
    table: dict[str, Any] = Field(default_factory=dict)


class NftablesChainRequest(BaseModel):
    chain: dict[str, Any] = Field(default_factory=dict)


class NftablesTablesResponse(BaseModel):
    tables: list[dict[str, Any]]


class NftablesTableResponse(BaseModel):
    table: dict[str, Any]


class NftablesTableChainsResponse(BaseModel):
    table: str
    chains: list[dict[str, Any]]


class NftablesTableChainResponse(BaseModel):
    table: str
    chain: dict[str, Any]
