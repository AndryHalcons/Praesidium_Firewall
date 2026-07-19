"""Repositorio del módulo Monitor Logs."""

from __future__ import annotations

from pathlib import Path

from storage.paths import STATE_DIR

LOG_DIR = Path("/var/log/praesidium")
MONITOR_STATE_DIR = STATE_DIR / "monitor_log"


def log_dir() -> Path:
    """Devuelve directorio de logs Praesidium."""
    return LOG_DIR


def state_dir() -> Path:
    """Devuelve state/monitor_log."""
    MONITOR_STATE_DIR.mkdir(parents=True, exist_ok=True)
    return MONITOR_STATE_DIR
