"""
Configuración básica de la API FastAPI de Praesidium.
Basic configuration for the Praesidium FastAPI API.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _load_or_create_secret() -> str:
    """Carga secreto JWT por entorno o crea uno persistente local."""
    env_secret = os.environ.get("PRAESIDIUM_API_TOKEN_SECRET")
    if env_secret:
        return env_secret
    secret_path = Path(os.environ.get("PRAESIDIUM_API_TOKEN_SECRET_FILE", "/var/lib/praesidium/state/api_token_secret"))
    try:
        if secret_path.exists():
            value = secret_path.read_text(encoding="utf-8").strip()
            if value:
                return value
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_urlsafe(64)
        secret_path.write_text(value + "\n", encoding="utf-8")
        secret_path.chmod(0o600)
        return value
    except OSError:
        # ES: Fallback temporal no determinista si el FS no permite persistir.
        # EN: Non-deterministic temporary fallback if the FS cannot persist.
        return secrets.token_urlsafe(64)


class Settings(BaseSettings):
    """Ajustes de aplicación. / Application settings."""

    model_config = SettingsConfigDict(env_prefix="PRAESIDIUM_")

    app_name: str = "praesidium-fastapi"
    app_version: str = "0.1.0"
    data_root: str = "/var/lib/praesidium"
    log_root: str = "/var/log/praesidium"
    api_token_secret: str = Field(default_factory=_load_or_create_secret)
    api_token_expires_minutes: int = 480


settings = Settings()
