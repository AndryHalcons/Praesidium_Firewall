"""Repositorio del módulo Monitor Session."""

from __future__ import annotations

from pathlib import Path

from storage.paths import STATE_DIR

SESSION_STATE_DIR = STATE_DIR / "sessions_contrack"
EXTRACTOR = Path("/var/lib/praesidium/scripts/checks/check_sessions_contrack/extract_session_contrack_xml.py")


def state_dir() -> Path:
    """Devuelve state/sessions_contrack."""
    SESSION_STATE_DIR.mkdir(parents=True, exist_ok=True)
    return SESSION_STATE_DIR


def snapshot_path(user_name: str) -> Path:
    """Ruta del snapshot XML por usuario validado."""
    return state_dir() / f"{user_name}_session_conntrack.xml"


def extractor_path() -> Path:
    """Ruta del extractor conntrack fijo."""
    return EXTRACTOR
