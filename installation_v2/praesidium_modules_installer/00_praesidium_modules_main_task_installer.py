#!/usr/bin/env python3
"""
ES: Ejecuta los instaladores de esta carpeta en orden numérico.
EN: Run the installers in this folder in numeric order.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ORDER_RE = re.compile(r"^(\d{2})_.*\.py$")


# ES: Devuelve los scripts .py numerados, excepto este main 00.
# EN: Return numbered .py scripts, excluding this 00 main.
def ordered_scripts() -> list[Path]:
    scripts: list[tuple[int, Path]] = []
    current = Path(__file__).resolve()
    for path in SCRIPT_DIR.glob("*.py"):
        resolved = path.resolve()
        if resolved == current:
            continue
        match = ORDER_RE.match(path.name)
        if not match:
            continue
        scripts.append((int(match.group(1)), path))
    return [path for _, path in sorted(scripts, key=lambda item: (item[0], item[1].name))]


# ES: Ejecuta cada script con el mismo intérprete de Python.
# EN: Run each script with the same Python interpreter.
def run_scripts() -> None:
    scripts = ordered_scripts()
    if not scripts:
        raise RuntimeError(f"No hay scripts numerados para ejecutar en {SCRIPT_DIR}")
    for script in scripts:
        command = [sys.executable, str(script)]
        print(f"[RUN] {script.name}", flush=True)
        subprocess.run(command, cwd=str(SCRIPT_DIR), check=True)


def main() -> int:
    run_scripts()
    print("[OK] instalación v2 completada", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
