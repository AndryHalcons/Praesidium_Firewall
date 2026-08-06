#!/usr/bin/env python3
"""
Preparador de estructura host para Praesidium/FastAPI.
Host structure preparer for Praesidium/FastAPI.

Crea los directorios persistentes, el directorio de aplicación y vuelca initial_config.
Create persistent directories, the application directory and copy initial_config.
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import shutil
from pathlib import Path


# Datos persistentes de Praesidium en el host. / Persistent host data.
DATA_ROOT = Path("/var/lib/praesidium")

# Logs persistentes de Praesidium en el host. / Persistent host logs.
LOG_ROOT = Path("/var/log/praesidium")

# Aplicación FastAPI instalada en el host. / FastAPI application installed on the host.
OPT_ROOT = Path("/opt/praesidium")
FASTAPI_ROOT = OPT_ROOT / "fastapi"

SERVICE_USER = "praesidium"
SERVICE_GROUP = "praesidium"

# Subdirectorios que FastAPI podrá usar para candidate/running/estado/scripts.
# Subdirectories FastAPI can use for candidate/running/state/scripts.
DATA_SUBDIRS = (
    "candidate",
    "running",
    "commits",
    "backups",
    "state",
    "scripts",
)


def require_root() -> None:
    """
    Exige root porque se crean rutas bajo /var.
    Require root because paths under /var are created.
    """
    if os.geteuid() != 0:
        raise SystemExit("ERROR: ejecuta este script con sudo/root")


def parse_octal(value: str) -> int:
    """Convierte '775' a permisos octales. / Convert '775' to octal mode."""
    try:
        return int(value, 8)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"modo inválido: {value}") from exc


def service_gid() -> int:
    """Devuelve el GID del grupo runtime Praesidium."""
    return grp.getgrnam(SERVICE_GROUP).gr_gid


def chown_root_service_group(path: Path) -> None:
    """Fija propietario root y grupo praesidium en una ruta existente."""
    os.chown(path, 0, service_gid())


def ensure_dir(path: Path, mode: int, *, group: str | None = SERVICE_GROUP) -> None:
    """
    Crea un directorio y fija propietario/grupo/permisos básicos.
    Create a directory and set owner/group/basic permissions.
    """
    path.mkdir(parents=True, exist_ok=True)
    if group == SERVICE_GROUP:
        chown_root_service_group(path)
    path.chmod(mode)
    owner_text = f" owner=root:{group}" if group else ""
    print(f"[OK] {path}{owner_text} mode={oct(mode)}")


def apply_data_tree_permissions(path: Path, directory_mode: int) -> None:
    """Aplica root:praesidium y permisos de lectura/escritura de grupo al árbol de datos."""
    if not path.exists():
        return
    gid = service_gid()
    for item in [path, *path.rglob("*")]:
        os.chown(item, 0, gid)
        if item.is_dir():
            item.chmod(directory_mode)
        elif item.is_file():
            item.chmod(0o664)


def ensure_praesidium_log_dir(path: Path) -> None:
    """
    Crea /var/log/praesidium con permisos compatibles con logrotate.
    Create /var/log/praesidium with logrotate-compatible permissions.
    """
    path.mkdir(parents=True, exist_ok=True)
    uid = pwd.getpwnam("syslog").pw_uid
    gid = grp.getgrnam("adm").gr_gid
    os.chown(path, uid, gid)
    path.chmod(0o750)
    print(f"[OK] {path} owner=syslog:adm mode=0o750")


def create_host_tree(data_mode: int, log_mode: int) -> None:
    """
    Crea la estructura de datos y aplicación del host.
    Create the host data and application structure.
    """
    ensure_dir(DATA_ROOT, data_mode)
    for name in DATA_SUBDIRS:
        ensure_dir(DATA_ROOT / name, data_mode)
    ensure_praesidium_log_dir(LOG_ROOT)
    ensure_dir(OPT_ROOT, 0o755, group=None)
    ensure_dir(FASTAPI_ROOT, 0o755)


# ES: Localiza la raíz del repositorio por la carpeta initial_config.
# EN: Locate the repository root by the initial_config folder.
def find_repo_root(start: Path) -> Path:
    for candidate in [start.resolve(), *start.resolve().parents]:
        if (candidate / ".git").exists() and (candidate / "initial_config").is_dir():
            return candidate
    raise RuntimeError("No se encontró la raíz del repo con .git e initial_config")


# ES: Copia initial_config sobre /var/lib/praesidium machacando los subdirectorios gestionados.
# EN: Copy initial_config over /var/lib/praesidium overwriting managed subdirectories.
def sync_initial_config(data_mode: int) -> None:
    repo_root = find_repo_root(Path(__file__).resolve().parent)
    source_root = repo_root / "initial_config"

    for name in DATA_SUBDIRS:
        source = source_root / name
        target = DATA_ROOT / name
        if not source.exists():
            print(f"[WARN] no existe {source}; se deja {target} vacío", flush=True)
            ensure_dir(target, data_mode)
            continue
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target, dirs_exist_ok=True)
        apply_data_tree_permissions(target, data_mode)
        print(f"[SYNC] {source} -> {target}", flush=True)



def parse_args() -> argparse.Namespace:
    """Parsea argumentos CLI. / Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Prepara host para Praesidium/FastAPI")
    parser.add_argument("--data-mode", type=parse_octal, default=0o775, help="Permisos de /var/lib/praesidium. Default: 775")
    parser.add_argument("--log-mode", type=parse_octal, default=0o750, help="Permisos de /var/log/praesidium. Default: 750")
    return parser.parse_args()


def main() -> int:
    """Punto de entrada. / Entry point."""
    args = parse_args()
    require_root()
    create_host_tree(args.data_mode, args.log_mode)
    sync_initial_config(args.data_mode)
    print("[OK] estructura host Praesidium/FastAPI preparada")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
