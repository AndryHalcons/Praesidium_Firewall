"""
Rutas persistentes de Praesidium en el host.
Praesidium persistent paths on the host.

La raíz de datos se define por configuración, con default estable:
The data root is defined by configuration, with a stable default:

    /var/lib/praesidium
"""

from __future__ import annotations

from pathlib import Path

from core.config import settings


# Raíz persistente del sistema host.
# Persistent root on the host system.
DATA_ROOT = Path(settings.data_root)

# Directorios principales de estado/configuración.
# Main state/configuration directories.
CANDIDATE_DIR = DATA_ROOT / "candidate"
RUNNING_DIR = DATA_ROOT / "running"
COMMITS_DIR = DATA_ROOT / "commits"
BACKUPS_DIR = DATA_ROOT / "backups"
STATE_DIR = DATA_ROOT / "state"
SCRIPTS_DIR = DATA_ROOT / "scripts"


def ensure_storage_tree() -> None:
    """
    Crea la estructura persistente si falta.
    Create the persistent structure if missing.

    Normalmente la crea el instalador 01 en el host, pero esta función
    permite una comprobación defensiva en el host.
    Normally installer 01 creates it on the host, but this function
    allows a defensive check on the host.
    """
    for directory in (
        DATA_ROOT,
        CANDIDATE_DIR,
        RUNNING_DIR,
        COMMITS_DIR,
        BACKUPS_DIR,
        STATE_DIR,
        SCRIPTS_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def config_path(area: str, filename: str) -> Path:
    """
    Devuelve una ruta de configuración controlada.
    Return a controlled configuration path.

    area permitido / allowed area:
        candidate, running, commits, backups, state, scripts
    """
    areas = {
        "candidate": CANDIDATE_DIR,
        "running": RUNNING_DIR,
        "commits": COMMITS_DIR,
        "backups": BACKUPS_DIR,
        "state": STATE_DIR,
        "scripts": SCRIPTS_DIR,
    }
    if area not in areas:
        raise ValueError(f"área de storage no permitida: {area}")
    if "/" in filename or filename.startswith("."):
        raise ValueError(f"nombre de fichero no permitido: {filename}")
    return areas[area] / filename
