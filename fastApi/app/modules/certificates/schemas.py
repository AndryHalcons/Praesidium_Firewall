"""Schemas Pydantic del módulo Certificates."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ModuleStatus(BaseModel):
    """Estado mínimo del módulo."""

    status: str
    module: str
    user: str | None = None


class CertificatesListResponse(BaseModel):
    """Listado de certificados."""

    certificates: list[dict[str, Any]]


class CertificateEntryResponse(BaseModel):
    """Certificado individual."""

    certificate: dict[str, Any]


class CertificateUploadResponse(BaseModel):
    """Resultado de subida."""

    success: bool
    file_name: str
    certificate: dict[str, Any]


class CertificateDeleteResponse(BaseModel):
    """Resultado de borrado."""

    success: bool
    file_name: str
