"""
Lectura y escritura JSON común para Praesidium FastAPI.
Common JSON reading and writing for Praesidium FastAPI.

Los módulos deben usar esta capa en vez de abrir rutas hardcodeadas.
Modules should use this layer instead of opening hardcoded paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from storage.atomic_write import atomic_write_text


def read_json(path: Path, default: Any | None = None) -> Any:
    """
    Lee JSON desde disco. Si no existe, devuelve default.
    Read JSON from disk. If missing, return default.
    """
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: Any) -> None:
    """
    Escribe JSON con formato estable y escritura atómica.
    Write JSON with stable formatting and atomic write.
    """
    content = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    atomic_write_text(path, content)
