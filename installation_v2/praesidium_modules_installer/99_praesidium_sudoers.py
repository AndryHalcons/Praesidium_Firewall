#!/usr/bin/env python3
"""
Instala sudoers mínimos para scripts Praesidium privilegiados.
Installs minimal sudoers entries for privileged Praesidium scripts.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

SUDOERS_DIR = Path("/etc/sudoers.d")
SUDOERS_FILE = SUDOERS_DIR / "praesidium"
SERVICE_USER = "praesidium"


@dataclass(frozen=True)
class SudoersRule:
    """Regla declarativa para permitir un comando concreto al usuario del servicio."""

    comment_es: str
    comment_en: str
    run_as: str
    command: str
    arguments: str = "*"

    # ES: Renderiza una regla sudoers con comentario bilingüe y comando cerrado.
    # EN: Renders a sudoers rule with bilingual comment and closed command.
    def render(self) -> list[str]:
        suffix = f" {self.arguments}" if self.arguments else ""
        return [
            f"# ES: {self.comment_es}",
            f"# EN: {self.comment_en}",
            f"{SERVICE_USER} ALL=({self.run_as}) NOPASSWD: {self.command}{suffix}",
        ]


# ES: Añadir futuras excepciones aquí, nunca concatenarlas en código procedural.
# EN: Add future exceptions here; never concatenate them in procedural code.
SUDOERS_RULES: tuple[SudoersRule, ...] = (
    SudoersRule(
        comment_es="Permite a FastAPI ejecutar sólo el wrapper controlado de conntrack para monitor_session.",
        comment_en="Allows FastAPI to run only the controlled conntrack wrapper for monitor_session.",
        run_as="root",
        command="/usr/bin/python3 /var/lib/praesidium/scripts/checks/check_sessions_contrack/extract_session_contrack_xml.py",
        arguments="*",
    ),
    SudoersRule(
        comment_es="Permite a FastAPI ejecutar sólo el apply controlado del módulo commit.",
        comment_en="Allows FastAPI to run only the controlled apply script for the commit module.",
        run_as="root",
        command="/usr/bin/python3 /var/lib/praesidium/scripts/commits/commit_apply.py",
        arguments="*",
    ),
    SudoersRule(
        comment_es="Permite a FastAPI ejecutar sólo el extractor controlado de rutas del sistema para routing.",
        comment_en="Allows FastAPI to run only the controlled system routes extractor for routing.",
        run_as="root",
        command="/usr/bin/python3 /var/lib/praesidium/scripts/checks/check_routes/check_system_routes_running.py",
        arguments="",
    ),
)


# ES: Construye el contenido completo de /etc/sudoers.d/praesidium desde reglas declarativas.
# EN: Builds the complete /etc/sudoers.d/praesidium content from declarative rules.
def render_sudoers() -> str:
    lines = [
        "# Managed by Praesidium installer.",
        "# Do not edit manually; update installation_v2/praesidium_modules_installer/99_praesidium_sudoers.py.",
        "",
    ]
    for index, rule in enumerate(SUDOERS_RULES):
        if index:
            lines.append("")
        lines.extend(rule.render())
    return "\n".join(lines) + "\n"


# ES: Valida con visudo un contenido sudoers antes de instalarlo.
# EN: Validates sudoers content with visudo before installing it.
def validate_sudoers_content(content: str) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(content)
        tmp_path = Path(handle.name)
    try:
        subprocess.run(["/usr/sbin/visudo", "-cf", str(tmp_path)], check=True)
    finally:
        tmp_path.unlink(missing_ok=True)


# ES: Escribe /etc/sudoers.d/praesidium de forma atómica con permisos 0440.
# EN: Writes /etc/sudoers.d/praesidium atomically with 0440 permissions.
def install_sudoers() -> None:
    content = render_sudoers()
    validate_sudoers_content(content)
    SUDOERS_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".praesidium.", dir=SUDOERS_DIR)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chown(tmp_path, 0, 0)
        tmp_path.chmod(0o440)
        subprocess.run(["/usr/sbin/visudo", "-cf", str(tmp_path)], check=True)
        os.replace(tmp_path, SUDOERS_FILE)
        os.chown(SUDOERS_FILE, 0, 0)
        SUDOERS_FILE.chmod(0o440)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


if __name__ == "__main__":
    install_sudoers()
