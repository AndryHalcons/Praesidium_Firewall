"""
Router API v1 de Praesidium.
Praesidium API v1 router.

Este router conecta endpoints generales y módulos funcionales.
This router connects general endpoints and functional modules.
"""

from __future__ import annotations

from fastapi import APIRouter

from core.config import settings
from modules.router import modules_router


api_router = APIRouter()


@api_router.get("/info")
def api_info() -> dict[str, str]:
    """Endpoint informativo de API v1. / Informational API v1 endpoint."""
    return {
        "status": "ok",
        "api": "v1",
        "service": settings.app_name,
        "version": settings.app_version,
    }


api_router.include_router(modules_router)
