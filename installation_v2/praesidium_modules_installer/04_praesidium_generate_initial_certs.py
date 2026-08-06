#!/usr/bin/env python3
"""
ES:
    Generador inicial de certificados de gestión para Praesidium.

    Este script crea una cadena PKI local y única para la instalación actual.
    Por defecto escribe en /var/lib/praesidium/candidate/certificates,
    copia a /var/lib/praesidium/running/certificates y usa el prefijo histórico
    solicitado `praesidium_management_`.

EN:
    Initial management certificate generator for Praesidium.

    This script creates a local, unique PKI chain for the current installation.
    By default it writes to /var/lib/praesidium/candidate/certificates,
    copies to /var/lib/praesidium/running/certificates and uses the requested
    historical prefix `praesidium_management_`.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_OUTPUT_DIR = Path("/var/lib/praesidium/candidate/certificates")
DEFAULT_RUNNING_CERTIFICATES_DIR = Path("/var/lib/praesidium/running/certificates")
DEFAULT_MANAGEMENT_JSON = Path("/var/lib/praesidium/candidate/management.json")
DEFAULT_RUNNING_MANAGEMENT_JSON = Path("/var/lib/praesidium/running/management.json")
DEFAULT_PREFIX = "praesidium_management"
DEFAULT_DAYS_ROOT = 3650
DEFAULT_DAYS_CA = 1825
DEFAULT_DAYS_CERT = 825
SERVICE_GROUP = "praesidium"


class CertGenerationError(RuntimeError):
    """ES: Error controlado generando certificados. EN: Controlled certificate generation error."""


# ES: Ejecuta OpenSSL sin shell para evitar problemas de quoting.
# EN: Run OpenSSL without a shell to avoid quoting issues.
def run_openssl(args: list[str], *, dry_run: bool) -> None:
    command = ["openssl", *args]
    print("[CMD] " + " ".join(command), flush=True)
    if dry_run:
        return

    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, file=sys.stdout)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr)
        raise CertGenerationError(f"openssl failed: {' '.join(command)}")


# ES: Devuelve los ficheros mínimos que Apache necesita para el TLS de gestión.
# EN: Return the minimum files Apache needs for management TLS.
def required_tls_files(output_dir: Path, *, prefix: str) -> dict[str, Path]:
    return {
        "certificate_file": output_dir / f"{prefix}_cert.pem",
        "certificate_key": output_dir / f"{prefix}_key.key",
        "certificate_chain": output_dir / f"{prefix}_chain.pem",
    }


# ES: Devuelve todos los ficheros gestionados por este generador.
# EN: Return all files managed by this generator.
def managed_files(output_dir: Path, *, prefix: str) -> list[Path]:
    patterns = (
        f"{prefix}_*.key",
        f"{prefix}_*.csr",
        f"{prefix}_*.pem",
        f"{prefix}_*.srl",
        f"{prefix}_*.cnf",
    )
    existing: list[Path] = []
    if output_dir.exists():
        for pattern in patterns:
            existing.extend(output_dir.glob(pattern))
    return sorted(set(existing))


# ES: Comprueba si la cadena TLS mínima ya está creada.
# EN: Check whether the minimum TLS chain already exists.
def certificate_chain_exists(output_dir: Path, *, prefix: str) -> bool:
    return all(path.is_file() for path in required_tls_files(output_dir, prefix=prefix).values())


# ES: Prepara el directorio sin sobrescribir certificados salvo regeneración forzada.
# EN: Prepare the directory without overwriting certificates unless forced regeneration is requested.
def ensure_output_dir(output_dir: Path, *, prefix: str, force: bool, dry_run: bool) -> None:
    existing = managed_files(output_dir, prefix=prefix)

    if dry_run:
        print(f"[DRY-RUN] mkdir -p {output_dir}", flush=True)
        if existing:
            names = ", ".join(path.name for path in existing)
            action = "would remove" if force else "would keep"
            print(f"[DRY-RUN] {action} existing managed files in {output_dir}: {names}", flush=True)
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    if existing and force:
        for path in existing:
            path.unlink()


# ES: Escribe el archivo de extensiones X509 usado al firmar CA y certificado servidor.
# EN: Write the X509 extension file used to sign CA and server certificate.
def write_extension_file(path: Path, *, dry_run: bool) -> None:
    content = """[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ alt_names ]
DNS.1 = praesidium.local
DNS.2 = server.praesidium.local
DNS.3 = localhost
IP.1 = 127.0.0.1
"""
    print(f"[WRITE] {path}", flush=True)
    if dry_run:
        return
    path.write_text(content, encoding="utf-8")


# ES: Ajusta permisos: claves privadas root:praesidium 640, certificados públicos legibles.
# EN: Set permissions: private keys root:praesidium 640, public certificates readable.
def secure_permissions(output_dir: Path, *, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY-RUN] chmod/chown private/public cert material under {output_dir}", flush=True)
        return

    gid = grp.getgrnam(SERVICE_GROUP).gr_gid
    os.chown(output_dir, 0, gid)
    output_dir.chmod(0o750)
    for path in output_dir.glob("praesidium_management_*.key"):
        os.chown(path, 0, gid)
        path.chmod(0o640)
    for pattern in ("praesidium_management_*.pem", "praesidium_management_*.csr", "praesidium_management_*.srl", "praesidium_management_*.cnf"):
        for path in output_dir.glob(pattern):
            os.chown(path, 0, gid)
            path.chmod(0o644)


def update_management_tls(management_json: Path, output_dir: Path, *, prefix: str, dry_run: bool, overwrite: bool = False) -> None:
    """
    ES: Rellena table_management_tls con los nombres de la cadena generada.
    EN: Fill table_management_tls with the generated chain file names.
    """
    tls_files = required_tls_files(output_dir, prefix=prefix)
    tls_row = {
        "id": "1",
        "certificate_file": tls_files["certificate_file"].name,
        "certificate_key": tls_files["certificate_key"].name,
        "certificate_chain": tls_files["certificate_chain"].name,
    }

    print(f"[WRITE] management TLS defaults in {management_json}", flush=True)
    if dry_run:
        return

    if management_json.exists():
        with management_json.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise CertGenerationError(f"invalid management JSON root: {management_json}")
    else:
        data = {}

    current = (data.get("table_management_tls") or [{}])[0]
    current_values = [str(current.get(field, "")).strip() for field in ("certificate_file", "certificate_key", "certificate_chain")]
    if current_values != ["", "", ""] and not overwrite:
        print(f"[OK] management TLS defaults already set in {management_json}; keeping existing selection", flush=True)
        return

    # ES: Conserva metadatos internos como UUID cuando se rellena el TLS inicial.
    # EN: Preserve internal metadata such as UUID when initial TLS is populated.
    if isinstance(current, dict) and current.get("UUID"):
        tls_row = {
            "id": "1",
            "UUID": str(current["UUID"]),
            "certificate_file": tls_row["certificate_file"],
            "certificate_key": tls_row["certificate_key"],
            "certificate_chain": tls_row["certificate_chain"],
        }

    data["table_management_tls"] = [tls_row]
    management_json.parent.mkdir(parents=True, exist_ok=True)
    management_json.write_text(json.dumps(data, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")


# ES: Copia los certificados candidate al árbol running tras generarlos/validarlos.
# EN: Copy candidate certificates to the running tree after generation/validation.
def sync_running_certificates(candidate_dir: Path, running_dir: Path, *, prefix: str, dry_run: bool) -> None:
    managed = managed_files(candidate_dir, prefix=prefix)
    if dry_run:
        print(f"[DRY-RUN] sync {candidate_dir} -> {running_dir}", flush=True)
        return
    running_dir.mkdir(parents=True, exist_ok=True)
    os.chown(running_dir, 0, grp.getgrnam(SERVICE_GROUP).gr_gid)
    running_dir.chmod(0o750)
    for existing in managed_files(running_dir, prefix=prefix):
        existing.unlink()
    for source in managed:
        target = running_dir / source.name
        shutil.copy2(source, target)
        os.chown(target, 0, grp.getgrnam(SERVICE_GROUP).gr_gid)
        target.chmod(source.stat().st_mode & 0o777)
    print(f"[SYNC] {candidate_dir} -> {running_dir}", flush=True)


# ES: Genera root CA, CA intermedia de gestión y certificado de servidor.
# EN: Generate root CA, management intermediate CA and server certificate.
def generate_chain(output_dir: Path, *, prefix: str, force: bool, dry_run: bool) -> bool:
    if shutil.which("openssl") is None:
        raise CertGenerationError("openssl command not found")

    ensure_output_dir(output_dir, prefix=prefix, force=force, dry_run=dry_run)

    if certificate_chain_exists(output_dir, prefix=prefix) and not force:
        print(f"[OK] Existing Praesidium management certificate chain found in {output_dir}; keeping it", flush=True)
        return False

    root_key = output_dir / f"{prefix}_rootCA.key"
    root_pem = output_dir / f"{prefix}_rootCA.pem"
    ca_key = output_dir / f"{prefix}_ca.key"
    ca_csr = output_dir / f"{prefix}_ca.csr"
    ca_pem = output_dir / f"{prefix}_ca.pem"
    ca_srl = output_dir / f"{prefix}_rootCA.srl"
    cert_key = output_dir / f"{prefix}_key.key"
    cert_csr = output_dir / f"{prefix}_csr.csr"
    cert_pem = output_dir / f"{prefix}_cert.pem"
    cert_srl = output_dir / f"{prefix}_ca.srl"
    chain_pem = output_dir / f"{prefix}_chain.pem"
    fullchain_pem = output_dir / f"{prefix}_fullchain.pem"
    ext_cnf = output_dir / f"{prefix}_openssl_ext.cnf"

    write_extension_file(ext_cnf, dry_run=dry_run)

    # ES: Root CA autofirmada de la instalación.
    # EN: Self-signed installation root CA.
    run_openssl(["genrsa", "-out", str(root_key), "4096"], dry_run=dry_run)
    run_openssl([
        "req", "-x509", "-new", "-nodes", "-key", str(root_key), "-sha256",
        "-days", str(DEFAULT_DAYS_ROOT), "-out", str(root_pem),
        "-subj", "/C=ES/O=Praesidium/OU=ManagementRootCA/CN=Praesidium Management Root CA",
    ], dry_run=dry_run)

    # ES: CA de gestión firmada por la root CA.
    # EN: Management CA signed by the root CA.
    run_openssl(["genrsa", "-out", str(ca_key), "4096"], dry_run=dry_run)
    run_openssl([
        "req", "-new", "-key", str(ca_key), "-out", str(ca_csr),
        "-subj", "/C=ES/O=Praesidium/OU=ManagementCA/CN=Praesidium Management CA",
    ], dry_run=dry_run)
    run_openssl([
        "x509", "-req", "-in", str(ca_csr), "-CA", str(root_pem), "-CAkey", str(root_key),
        "-CAcreateserial", "-out", str(ca_pem), "-days", str(DEFAULT_DAYS_CA), "-sha256",
        "-extfile", str(ext_cnf), "-extensions", "v3_ca",
    ], dry_run=dry_run)

    # ES: Certificado de servidor de gestión firmado por la CA de gestión.
    # EN: Management server certificate signed by the management CA.
    run_openssl(["genrsa", "-out", str(cert_key), "4096"], dry_run=dry_run)
    run_openssl([
        "req", "-new", "-key", str(cert_key), "-out", str(cert_csr),
        "-subj", "/C=ES/O=Praesidium/OU=Management/CN=praesidium.local",
    ], dry_run=dry_run)
    run_openssl([
        "x509", "-req", "-in", str(cert_csr), "-CA", str(ca_pem), "-CAkey", str(ca_key),
        "-CAcreateserial", "-out", str(cert_pem), "-days", str(DEFAULT_DAYS_CERT), "-sha256",
        "-extfile", str(ext_cnf), "-extensions", "server_cert",
    ], dry_run=dry_run)

    print(f"[WRITE] {chain_pem}", flush=True)
    print(f"[WRITE] {fullchain_pem}", flush=True)
    if not dry_run:
        chain_pem.write_text(ca_pem.read_text(encoding="utf-8") + root_pem.read_text(encoding="utf-8"), encoding="utf-8")
        fullchain_pem.write_text(cert_pem.read_text(encoding="utf-8") + chain_pem.read_text(encoding="utf-8"), encoding="utf-8")

    secure_permissions(output_dir, dry_run=dry_run)

    created = [
        root_key, root_pem, ca_key, ca_csr, ca_pem, ca_srl,
        cert_key, cert_csr, cert_pem, cert_srl, chain_pem, fullchain_pem, ext_cnf,
    ]
    print("[OK] Praesidium management certificate chain generated", flush=True)
    for path in created:
        print(f"  - {path}", flush=True)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Praesidium initial management certificates.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory where certificates are written.")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX, help="Output file prefix.")
    parser.add_argument("--management-json", default=str(DEFAULT_MANAGEMENT_JSON), help="Candidate management.json file to update after generation.")
    parser.add_argument("--running-certificates-dir", default=str(DEFAULT_RUNNING_CERTIFICATES_DIR), help="Directory where certificates are copied for running config.")
    parser.add_argument("--running-management-json", default=str(DEFAULT_RUNNING_MANAGEMENT_JSON), help="Running management.json file to update after generation.")
    parser.add_argument("--force", action="store_true", help="Regenerate and replace existing managed files.")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without writing files.")
    args = parser.parse_args(argv)

    try:
        output_dir = Path(args.output_dir)
        generated = generate_chain(output_dir, prefix=args.prefix, force=args.force, dry_run=args.dry_run)
        if generated or certificate_chain_exists(output_dir, prefix=args.prefix):
            update_management_tls(
                Path(args.management_json),
                output_dir,
                prefix=args.prefix,
                dry_run=args.dry_run,
                overwrite=generated or args.force,
            )
            sync_running_certificates(
                output_dir,
                Path(args.running_certificates_dir),
                prefix=args.prefix,
                dry_run=args.dry_run,
            )
            update_management_tls(
                Path(args.running_management_json),
                Path(args.running_certificates_dir),
                prefix=args.prefix,
                dry_run=args.dry_run,
                overwrite=generated or args.force,
            )
    except CertGenerationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
