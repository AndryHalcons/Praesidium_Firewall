#!/usr/bin/env python3
"""
ES: Permisos finales explícitos para rutas runtime Praesidium.
EN: Explicit final permissions for Praesidium runtime paths.
"""

from __future__ import annotations

import grp
import os
import pwd
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PermissionRule:
    """ES: Regla legible de permisos. EN: Readable permission rule."""

    path: Path
    owner: str
    group: str
    directory_mode: int
    file_mode: int | None = None
    recursive: bool = False
    create_directory: bool = False
    description_es: str = ""
    description_en: str = ""


# ES: Editar aquí las rutas y permisos finales del runtime.
# EN: Edit final runtime paths and permissions here.
PERMISSION_RULES: tuple[PermissionRule, ...] = (
    PermissionRule(
        path=Path("/var/lib/praesidium/candidate/certificates"),
        owner="root",
        group="praesidium",
        directory_mode=0o770,
        file_mode=None,
        recursive=False,
        create_directory=True,
        description_es="Directorio de certificados candidate: FastAPI necesita escritura de grupo.",
        description_en="Candidate certificates directory: FastAPI needs group write access.",
    ),
    PermissionRule(
        path=Path("/var/lib/praesidium/scripts"),
        owner="root",
        group="root",
        directory_mode=0o755,
        file_mode=0o644,
        recursive=True,
        create_directory=False,
        description_es="Código runtime ejecutado por FastAPI/sudoers: praesidium puede leer, pero no modificar.",
        description_en="Runtime code executed by FastAPI/sudoers: praesidium can read, but not modify.",
    ),
)


def uid_for(user_name: str) -> int:
    """ES: UID por nombre. EN: UID by name."""
    return pwd.getpwnam(user_name).pw_uid


def gid_for(group_name: str) -> int:
    """ES: GID por nombre. EN: GID by name."""
    return grp.getgrnam(group_name).gr_gid


def apply_one(path: Path, uid: int, gid: int, mode: int) -> None:
    """ES: Aplica dueño/grupo/permisos a una ruta. EN: Apply owner/group/mode to a path."""
    os.chown(path, uid, gid)
    path.chmod(mode)


def apply_rule(rule: PermissionRule) -> None:
    """ES: Aplica una regla explícita. EN: Apply one explicit rule."""
    if not rule.path.exists():
        if not rule.create_directory:
            print(f"[SKIP] {rule.path} does not exist")
            return
        rule.path.mkdir(parents=True, exist_ok=True)

    uid = uid_for(rule.owner)
    gid = gid_for(rule.group)

    targets = [rule.path]
    if rule.recursive:
        targets.extend(rule.path.rglob("*"))

    for target in targets:
        if target.is_dir():
            apply_one(target, uid, gid, rule.directory_mode)
        elif target.is_file():
            mode = rule.file_mode if rule.file_mode is not None else rule.directory_mode
            apply_one(target, uid, gid, mode)

    file_mode_text = "same-as-directory" if rule.file_mode is None else oct(rule.file_mode)
    print(
        f"[OK] {rule.path} owner={rule.owner}:{rule.group} "
        f"dir_mode={oct(rule.directory_mode)} file_mode={file_mode_text} recursive={rule.recursive}"
    )


def main() -> None:
    """ES: Aplica todas las reglas explícitas. EN: Apply all explicit rules."""
    for rule in PERMISSION_RULES:
        apply_rule(rule)


if __name__ == "__main__":
    main()
