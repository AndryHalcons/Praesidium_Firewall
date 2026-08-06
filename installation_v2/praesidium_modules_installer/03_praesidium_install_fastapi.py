#!/usr/bin/env python3
"""
ES: Instalador no-Docker de FastAPI para Praesidium.
EN: Non-Docker FastAPI installer for Praesidium.

ES: Despliega la API como servicio systemd usando /opt/praesidium/fastapi,
    un entorno virtual local y dependencias Python ya incluidas en el repositorio.
EN: Deploys the API as a systemd service using /opt/praesidium/fastapi,
    a local virtual environment and Python dependencies already vendored in the repository.
"""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


# ES: Carpeta donde vive este instalador numerado dentro de installation_v2.
# EN: Directory containing this numbered installer inside installation_v2.
SCRIPT_DIR = Path(__file__).resolve().parent

# ES: Nombre público del servicio FastAPI gestionado por systemd.
# EN: Public name of the FastAPI service managed by systemd.
SERVICE_NAME = "praesidium-fastapi"
SERVICE_USER = "praesidium"
SERVICE_GROUP = "praesidium"
LOG_READ_GROUP = "adm"
UNIT_PATH = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")

# ES: Rutas de instalación de la aplicación no-Docker bajo /opt.
# EN: Non-Docker application installation paths under /opt.
APP_ROOT = Path("/opt/praesidium/fastapi")
APP_DIR = APP_ROOT / "app"
DEPENDENCIES_DIR = APP_ROOT / "dependencies"
REQUIREMENTS_FILE = APP_ROOT / "requirements.txt"
VENV_DIR = APP_ROOT / ".venv"
ENV_FILE = APP_ROOT / ".env"

# ES: Rutas runtime preparadas por el instalador de storage y usadas por FastAPI.
# EN: Runtime paths prepared by the storage installer and used by FastAPI.
DATA_ROOT = Path("/var/lib/praesidium")
LOG_ROOT = Path("/var/log/praesidium")
HEALTH_URL = "http://127.0.0.1:8000/health"


def run(command: list[str], cwd: Path | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    """
    ES: Ejecuta comandos críticos del instalador con salida visible para auditoría.
    EN: Runs critical installer commands with visible output for auditing.
    """
    print(f"[CMD] {' '.join(command)}", flush=True)
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def require_root() -> None:
    """
    ES: Garantiza permisos suficientes para escribir en /opt y /etc/systemd.
    EN: Ensures enough privileges to write under /opt and /etc/systemd.
    """
    if os.geteuid() != 0:
        raise SystemExit("ERROR: ejecuta este script como root")


def find_repo_root(start: Path) -> Path:
    """
    ES: Localiza la raíz del repositorio usando la aplicación FastAPI como marcador.
    EN: Locates the repository root by using the FastAPI application as marker.
    """
    for candidate in [start.resolve(), *start.resolve().parents]:
        if (candidate / "fastApi" / "app" / "main.py").is_file():
            return candidate
    raise RuntimeError("No se encontró la raíz del repo con fastApi/app/main.py")


def service_uid() -> int:
    """Devuelve el UID del usuario runtime Praesidium."""
    return pwd.getpwnam(SERVICE_USER).pw_uid


def service_gid() -> int:
    """Devuelve el GID del grupo runtime Praesidium."""
    return grp.getgrnam(SERVICE_GROUP).gr_gid


def chown_root_service_group(path: Path) -> None:
    """Fija root:praesidium en una ruta existente."""
    os.chown(path, 0, service_gid())


def apply_fastapi_tree_permissions(path: Path) -> None:
    """Aplica permisos para que systemd ejecute FastAPI como praesidium."""
    if not path.exists():
        return
    gid = service_gid()
    for item in [path, *path.rglob("*")]:
        os.chown(item, 0, gid)
        if item.is_dir():
            item.chmod(0o755)
        elif item.is_file():
            mode = item.stat().st_mode & 0o777
            if mode & 0o111:
                item.chmod(0o755)
            else:
                item.chmod(0o644)


def ensure_prerequisites() -> None:
    """
    ES: Valida que el 01 creó las rutas runtime y que el repo contiene fastApi completo.
    EN: Validates that 01 created runtime paths and that the repo contains full fastApi sources.
    """
    required_runtime = [
        APP_ROOT,
        DATA_ROOT,
        DATA_ROOT / "candidate",
        DATA_ROOT / "running",
        DATA_ROOT / "commits",
        DATA_ROOT / "backups",
        DATA_ROOT / "state",
        DATA_ROOT / "scripts",
        LOG_ROOT,
    ]
    for account in (SERVICE_USER,):
        pwd.getpwnam(account)
    for group in (SERVICE_GROUP, LOG_READ_GROUP):
        grp.getgrnam(group)

    missing_runtime = [str(path) for path in required_runtime if not path.exists()]
    if missing_runtime:
        raise RuntimeError("Faltan rutas runtime requeridas: " + ", ".join(missing_runtime))

    source_root = find_repo_root(SCRIPT_DIR) / "fastApi"
    required_source = [
        source_root / "app" / "main.py",
        source_root / "requirements.txt",
        source_root / "dependencies",
    ]
    missing_source = [str(path) for path in required_source if not path.exists()]
    if missing_source:
        raise RuntimeError("Faltan fuentes FastAPI requeridas: " + ", ".join(missing_source))


def stop_service_if_exists() -> None:
    """
    ES: Detiene una instalación anterior para permitir reinstalación idempotente.
    EN: Stops a previous installation to allow idempotent reinstallation.
    """
    result = subprocess.run(["systemctl", "list-unit-files", f"{SERVICE_NAME}.service"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if SERVICE_NAME in result.stdout:
        subprocess.run(["systemctl", "stop", f"{SERVICE_NAME}.service"], check=False)


def copy_fastapi_project() -> None:
    """
    ES: Sincroniza la app, requirements y wheelhouse local desde el repo hacia /opt.
    EN: Syncs the app, requirements and local wheelhouse from the repo into /opt.
    """
    source_root = find_repo_root(SCRIPT_DIR) / "fastApi"

    for target in (APP_DIR, DEPENDENCIES_DIR):
        if target.exists():
            shutil.rmtree(target)

    shutil.copytree(source_root / "app", APP_DIR, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(source_root / "dependencies", DEPENDENCIES_DIR)
    shutil.copy2(source_root / "requirements.txt", REQUIREMENTS_FILE)

    print(f"[SYNC] {source_root / 'app'} -> {APP_DIR}", flush=True)
    print(f"[SYNC] {source_root / 'dependencies'} -> {DEPENDENCIES_DIR}", flush=True)
    print(f"[SYNC] {source_root / 'requirements.txt'} -> {REQUIREMENTS_FILE}", flush=True)
    apply_fastapi_tree_permissions(APP_ROOT)


def create_env_file() -> None:
    """
    ES: Genera el .env de runtime apuntando FastAPI a /var/lib y /var/log Praesidium.
    EN: Generates the runtime .env pointing FastAPI to Praesidium /var/lib and /var/log.
    """
    token_file = DATA_ROOT / "state" / "api_token_secret"
    env_lines = [
        "PRAESIDIUM_APP_NAME" + chr(61) + "praesidium-fastapi",
        "PRAESIDIUM_APP_VERSION" + chr(61) + "0.1.0",
        "PRAESIDIUM_DATA_ROOT" + chr(61) + str(DATA_ROOT),
        "PRAESIDIUM_LOG_ROOT" + chr(61) + str(LOG_ROOT),
        "PRAESIDIUM_API_TOKEN_" + "SECRET_FILE" + chr(61) + str(token_file),
        "PRAESIDIUM_API_TOKEN_EXPIRES_MINUTES" + chr(61) + str(480),
        "",
    ]
    ENV_FILE.write_text("\n".join(env_lines), encoding="utf-8")
    chown_root_service_group(ENV_FILE)
    ENV_FILE.chmod(0o640)
    print(f"[OK] {ENV_FILE} owner=root:{SERVICE_GROUP} mode=0o640", flush=True)


def recreate_venv() -> None:
    """
    ES: Recrea .venv e instala dependencias offline sin contactar PyPI ni Internet.
    EN: Recreates .venv and installs dependencies offline without contacting PyPI or Internet.
    """
    if VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    try:
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("No se pudo crear venv. Instala python3-venv/python3.12-venv en requirements del sistema.") from exc

    pip = VENV_DIR / "bin" / "pip"
    run([
        str(pip), "install",
        "--no-index",
        f"--find-links={DEPENDENCIES_DIR}",
        "-r", str(REQUIREMENTS_FILE),
    ])
    apply_fastapi_tree_permissions(VENV_DIR)


def write_systemd_unit() -> None:
    """
    ES: Escribe la unidad systemd que arranca Uvicorn ligado a 0.0.0.0:8000 para acceso de red.
    EN: Writes the systemd unit that starts Uvicorn bound to 0.0.0.0:8000 for network access.
    """
    unit = f"""[Unit]
Description=Praesidium FastAPI service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={APP_DIR}
EnvironmentFile={ENV_FILE}
ExecStart={VENV_DIR}/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=3
User={SERVICE_USER}
Group={SERVICE_GROUP}
SupplementaryGroups={LOG_READ_GROUP}

[Install]
WantedBy=multi-user.target
"""
    UNIT_PATH.write_text(unit, encoding="utf-8")
    UNIT_PATH.chmod(0o644)
    print(f"[OK] {UNIT_PATH} mode=0o644", flush=True)
    run(["systemctl", "daemon-reload"])


def enable_and_start_service() -> None:
    """
    ES: Habilita el servicio en arranque y reinicia FastAPI con la versión recién instalada.
    EN: Enables the service on boot and restarts FastAPI with the freshly installed version.
    """
    run(["systemctl", "enable", f"{SERVICE_NAME}.service"])
    run(["systemctl", "restart", f"{SERVICE_NAME}.service"])


def wait_health(timeout_seconds: int = 45) -> None:
    """
    ES: Comprueba que el servicio responde /health antes de dar la instalación por válida.
    EN: Checks that the service answers /health before considering installation valid.
    """
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=3) as response:
                body = response.read().decode("utf-8", errors="replace")
                if response.status == 200 and '"status":"ok"' in body.replace(" ", ""):
                    print(f"[OK] FastAPI health: {body}", flush=True)
                    return
                last_error = f"HTTP {response.status}: {body}"
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(2)
    subprocess.run(["systemctl", "status", f"{SERVICE_NAME}.service", "--no-pager", "-l"], check=False)
    raise RuntimeError(f"FastAPI no respondió correctamente en {HEALTH_URL}: {last_error}")


def install_fastapi() -> None:
    """
    ES: Orquesta la reinstalación completa FastAPI no-Docker de forma repetible.
    EN: Orchestrates the complete non-Docker FastAPI reinstallation repeatably.
    """
    require_root()
    ensure_prerequisites()
    stop_service_if_exists()
    copy_fastapi_project()
    create_env_file()
    recreate_venv()
    write_systemd_unit()
    enable_and_start_service()
    wait_health()


def main() -> int:
    install_fastapi()
    print("[OK] FastAPI no-Docker instalado", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
