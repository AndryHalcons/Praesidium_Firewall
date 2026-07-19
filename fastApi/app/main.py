"""
Aplicación FastAPI mínima de Praesidium.
Minimal Praesidium FastAPI application.

Este archivo solo define la entrada HTTP inicial y endpoints básicos de salud.
This file only defines the initial HTTP entry point and basic health endpoints.

La lógica real futura NO debe vivir aquí.
Future real logic must NOT live here.
"""

from __future__ import annotations

from fastapi import FastAPI

from core.config import settings
from api.v1.router import api_router


# Instancia principal de FastAPI.
# Main FastAPI instance.
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="API FastAPI de Praesidium desplegada como servicio systemd nativo.",
)


@app.get("/health")
def health() -> dict[str, str]:
    """
    Endpoint mínimo para comprobar que el servicio FastAPI responde.
    Minimal endpoint to check that the FastAPI service responds.
    """
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/")
def root() -> dict[str, str]:
    """
    Endpoint raíz informativo.
    Informational root endpoint.
    """
    return {
        "status": "ok",
        "message": "Praesidium FastAPI service running",
    }


# Router versionado para futuras APIs reales.
# Versioned router for future real APIs.
app.include_router(api_router, prefix="/api/v1")
