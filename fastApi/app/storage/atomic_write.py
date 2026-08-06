"""
Escritura atómica de ficheros de texto.
Atomic text file writing.

Evita dejar JSON corrupto si el proceso cae durante la escritura.
Avoids leaving corrupt JSON if the process dies during writing.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, content: str) -> None:
    """
    Escribe texto usando fichero temporal + fsync + rename atómico.
    Write text using temporary file + fsync + atomic rename.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    tmp_path = Path(tmp_name)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        finally:
            raise
