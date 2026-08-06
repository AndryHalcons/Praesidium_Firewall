"""Repositorio del módulo Certificates."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import fcntl

from storage.paths import CANDIDATE_DIR

CERTIFICATES_DIRNAME = "certificates"


def certificates_dir() -> Path:
    """Devuelve candidate/certificates."""
    path = CANDIDATE_DIR / CERTIFICATES_DIRNAME
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def certificates_lock():
    """Bloquea candidate/certificates durante scan/upload/delete."""
    path = certificates_dir()
    lock_path = path / ".certificates.lock"
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
