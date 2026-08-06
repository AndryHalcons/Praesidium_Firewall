"""Lógica de negocio FastAPI para Certificates."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, UploadFile, status

from modules.certificates import repository

COLUMNS = ["type", "file_name", "name", "subject", "issuer", "expires", "status", "algorithm"]
VALID_EXTENSIONS = {"pem", "crt", "cer", "csr", "req", "key", "srl", "cnf", "pfx", "p12", "pkcs12", "der", "jks"}
ORDER = ["root", "intermediate", "issuer", "client", "csr", "key", "serial", "config", "unknown"]
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,255}$")

# ES: La subida es deliberadamente más restrictiva que el indexador de archivos existentes.
# EN: Uploads are deliberately more restrictive than indexing existing files.
UPLOAD_EXTENSIONS = {"pem", "key", "crt", "csr", "srl", "p12", "pfx", "der", "cer", "pkcs12"}
SENSITIVE_UPLOAD_EXTENSIONS = {"key", "p12", "pfx", "pkcs12"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 64 * 1024


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """Lanza error estable status/error_code."""
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


def safe_file_name(file_name: str) -> str:
    """Valida nombre de fichero sin rutas."""
    name = str(file_name or "").strip()
    if not name or "/" in name or "\\" in name or name in {".", ".."} or not SAFE_FILENAME_RE.match(name):
        fail("CERTIFICATES_FILE_NAME_INVALID", status.HTTP_400_BAD_REQUEST)
    return name


def certificate_path(file_name: str) -> Path:
    """Devuelve ruta segura dentro del directorio de certificados."""
    name = safe_file_name(file_name)
    base = repository.certificates_dir().resolve()
    path = (base / name).resolve()
    if base not in path.parents and path != base:
        fail("CERTIFICATES_FILE_NAME_INVALID", status.HTTP_400_BAD_REQUEST)
    return path


def _run_openssl(args: list[str]) -> list[str]:
    """Ejecuta openssl sin shell y devuelve líneas."""
    proc = subprocess.run(["openssl", *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    if proc.returncode != 0:
        return []
    return proc.stdout.splitlines()


def _openssl_time_expired(value: str) -> bool:
    """Evalúa expiración notAfter de openssl."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            parsed = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return parsed < datetime.now(timezone.utc)
        except ValueError:
            continue
    return False


def _blank_entry(path: Path) -> dict[str, str]:
    """Entrada base para una fila."""
    return {
        "type": "unknown",
        "file_name": path.name,
        "name": path.stem,
        "subject": "",
        "issuer": "",
        "expires": "",
        "status": "",
        "algorithm": "",
    }


def inspect_certificate_file(path: Path) -> dict[str, str] | None:
    """Extrae metadata compatible con el legacy."""
    if not path.is_file():
        return None
    ext = path.suffix.lower().lstrip(".")
    if ext not in VALID_EXTENSIONS:
        return None
    entry = _blank_entry(path)

    if ext in {"pem", "crt", "cer", "der", "pfx", "p12", "pkcs12"}:
        lines = _run_openssl(["x509", "-in", str(path), "-noout", "-subject", "-issuer", "-enddate", "-text"])
        if lines:
            for line in lines:
                if line.startswith("subject="):
                    entry["subject"] = line[8:].strip()
                elif line.startswith("issuer="):
                    entry["issuer"] = line[7:].strip()
                elif line.startswith("notAfter="):
                    entry["expires"] = line[9:].strip()
                    entry["status"] = "expired" if _openssl_time_expired(entry["expires"]) else "valid"
                elif "Signature Algorithm:" in line and not entry["algorithm"]:
                    entry["algorithm"] = line.split(":", 1)[1].strip()
            if entry["issuer"] and entry["issuer"] == entry["subject"]:
                entry["type"] = "root"
            elif "intermediate" in path.name.lower():
                entry["type"] = "intermediate"
            elif "emisor" in path.name.lower() or "issuer" in path.name.lower():
                entry["type"] = "issuer"
            else:
                entry["type"] = "client"
    elif ext in {"csr", "req"}:
        lines = _run_openssl(["req", "-in", str(path), "-noout", "-subject"])
        if lines:
            first = lines[0]
            entry["subject"] = first[8:].strip() if first.startswith("subject=") else first.strip()
            entry["status"] = "pending"
        entry["type"] = "csr"
    elif ext == "key":
        entry["type"] = "key"
    elif ext == "srl":
        entry["type"] = "serial"
        entry["status"] = "serial"
    elif ext == "cnf":
        entry["type"] = "config"
    elif ext == "jks":
        entry["type"] = "unknown"
        entry["status"] = "unsupported"

    return {column: str(entry.get(column, "")) for column in COLUMNS}


def _scan_certificates_unlocked() -> list[dict[str, str]]:
    """Escanea candidate/certificates directamente sin tomar el lock."""
    # ES: El directorio es la única fuente de verdad; no se crea ningún índice JSON.
    # EN: The directory is the only source of truth; no JSON index is created.
    grouped: dict[str, list[dict[str, str]]] = {key: [] for key in ORDER}
    seen: set[str] = set()
    for path in sorted(repository.certificates_dir().iterdir(), key=lambda item: item.name):
        if path.name.startswith(".") or path.name in seen:
            continue
        entry = inspect_certificate_file(path)
        if entry is None:
            continue
        seen.add(path.name)
        grouped.setdefault(entry.get("type", "unknown"), []).append(entry)
    ordered: list[dict[str, str]] = []
    for key in ORDER:
        ordered.extend(grouped.get(key, []))
    return ordered


def scan_certificates() -> list[dict[str, str]]:
    """Escanea candidate/certificates usando el directorio como fuente de verdad."""
    with repository.certificates_lock():
        return _scan_certificates_unlocked()


def list_certificates() -> list[dict[str, str]]:
    """Lista certificados leyendo directamente el directorio."""
    return scan_certificates()


def get_certificate(file_name: str) -> dict[str, str]:
    """Lee directamente un archivo y devuelve sus metadatos."""
    name = safe_file_name(file_name)
    path = certificate_path(name)
    # ES: El lock evita que el archivo desaparezca mientras OpenSSL lo analiza.
    # EN: The lock prevents the file from disappearing while OpenSSL inspects it.
    with repository.certificates_lock():
        entry = inspect_certificate_file(path)
        if entry is None:
            fail("CERTIFICATES_FILE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        return entry


def download_path(file_name: str) -> Path:
    """Devuelve ruta descargable admin-only."""
    path = certificate_path(file_name)
    if not path.is_file():
        fail("CERTIFICATES_FILE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    return path


def _validate_upload_name(file_name: str) -> tuple[str, str]:
    """Valida el nombre y devuelve nombre normalizado y extensión."""
    # ES: Se valida el nombre completo; basename no debe ocultar intentos de traversal.
    # EN: Validate the complete name; basename must not hide traversal attempts.
    name = safe_file_name(file_name)
    if name.startswith("."):
        fail("CERTIFICATES_UPLOAD_FILE_NAME_INVALID", status.HTTP_400_BAD_REQUEST)

    extension = Path(name).suffix.lower().lstrip(".")
    if extension not in UPLOAD_EXTENSIONS:
        fail("CERTIFICATES_UPLOAD_EXTENSION_INVALID", status.HTTP_400_BAD_REQUEST)
    if not Path(name).stem:
        fail("CERTIFICATES_UPLOAD_FILE_NAME_INVALID", status.HTTP_400_BAD_REQUEST)
    return name, extension


def _openssl_accepts(path: Path, args: list[str]) -> bool:
    """Ejecuta OpenSSL sin shell, entrada interactiva ni salida sensible."""
    try:
        process = subprocess.run(
            ["openssl", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.returncode == 0


def _validate_upload_content(path: Path, extension: str) -> None:
    """Comprueba que el contenido criptográfico coincide con su extensión."""
    # ES: MIME y nombre no bastan; OpenSSL debe analizar el archivo real.
    # EN: MIME and filename are insufficient; OpenSSL must parse the real file.
    if extension in {"pem", "crt", "cer"}:
        valid = _openssl_accepts(path, ["x509", "-in", str(path), "-noout"])
    elif extension == "der":
        valid = _openssl_accepts(path, ["x509", "-inform", "DER", "-in", str(path), "-noout"])
    elif extension == "csr":
        valid = _openssl_accepts(path, ["req", "-in", str(path), "-noout", "-verify"])
    elif extension == "key":
        # ES: Sin contraseña se evitan prompts y secretos adicionales en esta primera versión.
        # EN: No password avoids prompts and extra secrets in this first version.
        valid = _openssl_accepts(path, ["pkey", "-in", str(path), "-noout", "-check", "-passin", "pass:"])
    elif extension in {"p12", "pfx", "pkcs12"}:
        # ES: Se aceptan sólo contenedores sin contraseña porque el endpoint no recibe secretos.
        # EN: Only passwordless containers are accepted because the endpoint receives no secrets.
        valid = _openssl_accepts(path, ["pkcs12", "-in", str(path), "-info", "-noout", "-passin", "pass:"])
    elif extension == "srl":
        try:
            serial = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            valid = False
        else:
            valid = bool(re.fullmatch(r"[0-9A-Fa-f]+", serial))
    else:
        valid = False

    if not valid:
        fail("CERTIFICATES_UPLOAD_CONTENT_INVALID", status.HTTP_422_UNPROCESSABLE_ENTITY)


async def upload_certificate(upload: UploadFile) -> dict[str, Any]:
    """Valida y guarda atómicamente un certificado candidato."""
    original_name, extension = _validate_upload_name(upload.filename or "")
    base_dir = repository.certificates_dir().resolve()
    # ES: Se conserva el nombre original; un nombre existente nunca se renombra ni sobrescribe.
    # EN: Preserve the original name; an existing name is never renamed or overwritten.
    final_name = original_name
    final_path = certificate_path(final_name)
    temporary_path: Path | None = None

    try:
        # ES: mkstemp crea un temporal privado e impredecible dentro del destino final.
        # EN: mkstemp creates a private unpredictable temporary inside the final destination.
        descriptor, temporary_name = tempfile.mkstemp(prefix=".certificate-upload-", dir=base_dir)
        temporary_path = Path(temporary_name)
        total = 0
        with os.fdopen(descriptor, "wb") as handle:
            while True:
                chunk = await upload.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    fail("CERTIFICATES_UPLOAD_TOO_LARGE", status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())

        if total == 0:
            fail("CERTIFICATES_UPLOAD_EMPTY", status.HTTP_400_BAD_REQUEST)
        _validate_upload_content(temporary_path, extension)

        # ES: El lock une la publicación final y la lectura de sus metadatos.
        # EN: The lock joins final publication and metadata inspection.
        with repository.certificates_lock():
            if final_path.exists():
                fail("CERTIFICATES_UPLOAD_CONFLICT", status.HTTP_409_CONFLICT)
            os.replace(temporary_path, final_path)
            temporary_path = None
            final_path.chmod(0o640 if extension in SENSITIVE_UPLOAD_EXTENSIONS else 0o644)
            try:
                certificate = inspect_certificate_file(final_path)
                if certificate is None:
                    fail("CERTIFICATES_UPLOAD_METADATA_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Exception:
                # ES: Un fallo de lectura revierte el archivo y evita una subida parcial.
                # EN: An inspection failure rolls the file back and avoids a partial upload.
                final_path.unlink(missing_ok=True)
                raise

        return {"success": True, "file_name": final_name, "certificate": certificate}
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "error_code": "CERTIFICATES_UPLOAD_FAILED"},
        ) from exc
    finally:
        # ES: Ningún error debe dejar temporales ni descriptores abiertos.
        # EN: No error may leave temporary files or descriptors open.
        await upload.close()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def delete_certificate(file_name: str) -> dict[str, Any]:
    """Borra directamente un certificado candidate."""
    path = certificate_path(file_name)
    with repository.certificates_lock():
        if not path.is_file():
            fail("CERTIFICATES_FILE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        try:
            path.unlink()
        except FileNotFoundError:
            fail("CERTIFICATES_FILE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        except OSError as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"status": "error", "error_code": "CERTIFICATES_DELETE_FAILED"}) from exc
    return {"success": True, "file_name": path.name}
