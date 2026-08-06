"""Servicio FastAPI del módulo Routing."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

STATE_FILE = Path("/var/lib/praesidium/state/routes/routes.json")
ROUTES_SCRIPT = "/var/lib/praesidium/scripts/checks/check_routes/check_system_routes_running.py"


def _empty_data() -> dict[str, Any]:
    return {"routes": [], "rules": [], "has_snapshot": False}


def _validate_data(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="ROUTING_STATE_INVALID")
    routes = data.get("routes", [])
    rules = data.get("rules", [])
    if not isinstance(routes, list) or not isinstance(rules, list):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="ROUTING_STATE_INVALID")
    return {"routes": routes, "rules": rules, "has_snapshot": True}


def read_routes() -> dict[str, Any]:
    """Lee el snapshot de rutas generado en state."""
    if not STATE_FILE.exists():
        return _empty_data()
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="ROUTING_STATE_JSON_INVALID") from exc
    return _validate_data(data)


def reload_routes() -> dict[str, Any]:
    """Ejecuta el extractor controlado y devuelve el snapshot actualizado."""
    result = subprocess.run(
        ["/usr/bin/sudo", "-n", "/usr/bin/python3", ROUTES_SCRIPT],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "status": "error",
                "error_code": "ROUTING_RELOAD_FAILED",
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            },
        )
    data = read_routes()
    return {
        "status": "ok",
        "routes": data["routes"],
        "rules": data["rules"],
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
