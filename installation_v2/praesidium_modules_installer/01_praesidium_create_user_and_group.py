#!/usr/bin/env python3
"""
ES: Crea el usuario/grupo de servicio Praesidium de forma idempotente.
EN: Create the Praesidium service user/group idempotently.
"""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
import sys


SERVICE_USER = "praesidium"
SERVICE_GROUP = "praesidium"
LOG_READ_GROUP = "adm"


def run(command: list[str]) -> None:
    """Ejecuta un comando del sistema mostrando la acción."""
    printable = " ".join(command)
    print(f"[RUN] {printable}", flush=True)
    subprocess.run(command, check=True)


def group_exists(group_name: str) -> bool:
    try:
        grp.getgrnam(group_name)
        return True
    except KeyError:
        return False


def user_exists(user_name: str) -> bool:
    try:
        pwd.getpwnam(user_name)
        return True
    except KeyError:
        return False


def user_groups(user_name: str) -> set[str]:
    result = subprocess.run(
        ["id", "-nG", user_name],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return set(result.stdout.strip().split())


def ensure_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Este script debe ejecutarse como root")


def ensure_service_group() -> None:
    if group_exists(SERVICE_GROUP):
        print(f"[OK] group exists: {SERVICE_GROUP}", flush=True)
        return
    run(["groupadd", "--system", SERVICE_GROUP])
    print(f"[OK] group created: {SERVICE_GROUP}", flush=True)


def ensure_service_user() -> None:
    if user_exists(SERVICE_USER):
        print(f"[OK] user exists: {SERVICE_USER}", flush=True)
        return
    run([
        "useradd",
        "--system",
        "--gid", SERVICE_GROUP,
        "--home-dir", "/nonexistent",
        "--no-create-home",
        "--shell", "/usr/sbin/nologin",
        SERVICE_USER,
    ])
    print(f"[OK] user created: {SERVICE_USER}", flush=True)


def ensure_log_read_group_membership() -> None:
    if not group_exists(LOG_READ_GROUP):
        raise RuntimeError(f"Required group does not exist: {LOG_READ_GROUP}")
    groups = user_groups(SERVICE_USER)
    if LOG_READ_GROUP in groups:
        print(f"[OK] {SERVICE_USER} already belongs to {LOG_READ_GROUP}", flush=True)
        return
    run(["usermod", "-aG", LOG_READ_GROUP, SERVICE_USER])
    print(f"[OK] added {SERVICE_USER} to {LOG_READ_GROUP}", flush=True)


def main() -> int:
    ensure_root()
    ensure_service_group()
    ensure_service_user()
    ensure_log_read_group_membership()
    print("[OK] Praesidium service identity ready", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr, flush=True)
        raise
