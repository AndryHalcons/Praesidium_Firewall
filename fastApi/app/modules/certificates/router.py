"""Router HTTP del módulo Certificates."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import FileResponse

from core.security.dependencies import current_active_user, require_admin
from modules.certificates.schemas import CertificateDeleteResponse, CertificateEntryResponse, CertificatesListResponse, CertificateUploadResponse, ModuleStatus
from modules.certificates.service import delete_certificate, download_path, get_certificate, list_certificates, upload_certificate

router = APIRouter(prefix="/certificates", tags=["certificates"])


@router.get("/status", response_model=ModuleStatus, summary="Certificates status")
def status_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, str]:
    """Comprueba que Certificates responde.

    Formato:
    ```text
    GET /api/v1/certificates/status
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/certificates/status
    ```
    """
    return {"status": "ok", "module": "certificates", "user": user["user_name"]}


@router.get("", response_model=CertificatesListResponse, summary="List certificates")
def list_certificates_endpoint(user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Lista certificados candidatos.

    Formato:
    ```text
    GET /api/v1/certificates
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/certificates
    ```
    """
    return {"certificates": list_certificates()}


@router.post("/upload", response_model=CertificateUploadResponse, summary="Upload certificate")
async def upload_certificate_endpoint(
    file: Annotated[UploadFile, File(description="Certificate file")],
    user: Annotated[dict[str, str], Depends(require_admin)],
) -> dict[str, Any]:
    """Sube y valida un certificado candidato.

    Formato:
    ```text
    POST /api/v1/certificates/upload
    ```

    Ejemplo de uso:
    ```text
    POST http://192.0.2.10:8000/api/v1/certificates/upload
    ```
    """
    # ES: La dependencia require_admin protege la escritura de material sensible.
    # EN: The require_admin dependency protects writes of sensitive material.
    return await upload_certificate(file)


@router.get("/{file_name}", response_model=CertificateEntryResponse, summary="Get certificate metadata")
def get_certificate_endpoint(file_name: str, user: Annotated[dict[str, str], Depends(current_active_user)]) -> dict[str, Any]:
    """Consulta metadata de un certificado.

    Formato:
    ```text
    GET /api/v1/certificates/{file_name}
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/certificates/praesidium_cert.pem
    ```
    """
    return {"certificate": get_certificate(file_name)}


@router.get("/{file_name}/download", summary="Download certificate file")
def download_certificate_endpoint(file_name: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> FileResponse:
    """Descarga un certificado o clave.

    Formato:
    ```text
    GET /api/v1/certificates/{file_name}/download
    ```

    Ejemplo de uso:
    ```text
    GET http://192.0.2.10:8000/api/v1/certificates/praesidium_cert.pem/download
    ```
    """
    path = download_path(file_name)
    return FileResponse(path=path, media_type="application/octet-stream", filename=path.name, headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})


@router.delete("/{file_name}", response_model=CertificateDeleteResponse, summary="Delete certificate file")
def delete_certificate_endpoint(file_name: str, user: Annotated[dict[str, str], Depends(require_admin)]) -> dict[str, Any]:
    """Borra un certificado candidato.

    Formato:
    ```text
    DELETE /api/v1/certificates/{file_name}
    ```

    Ejemplo de uso:
    ```text
    DELETE http://192.0.2.10:8000/api/v1/certificates/old_cert.pem
    ```
    """
    return delete_certificate(file_name)
