"""Tests destructivos de Certificates."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import urllib.request
import urllib.error

from common.runner import BASE_URL, call, require

BASE = "/api/v1/certificates"
CERT_DIR = Path("/var/lib/praesidium/candidate/certificates")
TEST_PREFIX = "tmp_fastapi_certificates_test"
CERT_FILE = CERT_DIR / f"{TEST_PREFIX}.pem"
KEY_FILE = CERT_DIR / f"{TEST_PREFIX}.key"
CONFIG_FILE = CERT_DIR / "certificates_config.json"
BACKUP_CONFIG = Path("/tmp/praesidium_certificates_config_before_test.json")


def _backup() -> None:
    if CONFIG_FILE.exists():
        shutil.copy2(CONFIG_FILE, BACKUP_CONFIG)
    elif BACKUP_CONFIG.exists():
        BACKUP_CONFIG.unlink()


def _restore(ctx) -> None:
    for path in [CERT_FILE, KEY_FILE]:
        if path.exists():
            path.unlink()
    if BACKUP_CONFIG.exists():
        shutil.copy2(BACKUP_CONFIG, CONFIG_FILE)
    elif CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
    ctx.log("RESTORE certificates test files removed")


def _create_cert(ctx) -> None:
    for path in [CERT_FILE, KEY_FILE]:
        if path.exists():
            path.unlink()
    result = subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(KEY_FILE), "-out", str(CERT_FILE), "-subj", "/CN=tmp-fastapi-certificates-test"
    ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(ctx, result.returncode == 0 and CERT_FILE.exists() and KEY_FILE.exists(), "test certificate generated", f"openssl failed: {result.stderr[-300:]}")
    CERT_FILE.chmod(0o664)
    KEY_FILE.chmod(0o640)


def _admin(ctx) -> bool:
    return ctx.identity.role == "admin"


def run(ctx) -> None:
    ctx.log("=== CERTIFICATES DESTRUCTIVE ===")
    _backup()
    try:
        if not _admin(ctx):
            for label, method, path in [
                ("negative-viewer download", "GET", f"{BASE}/{TEST_PREFIX}.pem/download"),
                ("negative-viewer delete", "DELETE", f"{BASE}/{TEST_PREFIX}.pem"),
            ]:
                status, payload = call(ctx, label, method, path)
                require(ctx, status == 403, f"{label} forbidden", f"{label} returned {status}")
            return

        _create_cert(ctx)
        status, payload = call(ctx, "list certificates after file creation", "GET", BASE)
        require(ctx, status == 200, f"list returned 200", f"list returned {status}: {payload}")
        certs = payload.get("certificates", []) if isinstance(payload, dict) else []
        found = next((entry for entry in certs if entry.get("file_name") == CERT_FILE.name), None)
        require(ctx, isinstance(found, dict), "test cert present in direct list", "test cert not found in direct list")
        require(ctx, found.get("type") == "root", f"test cert classified as root", f"unexpected type {found}")
        require(ctx, found.get("status") == "valid", f"test cert valid", f"unexpected status {found}")

        status, payload = call(ctx, "get test certificate", "GET", f"{BASE}/{CERT_FILE.name}")
        require(ctx, status == 200, f"get test cert ok", f"get test cert returned {status}: {payload}")
        certificate = payload.get("certificate", {}) if isinstance(payload, dict) else {}
        require(ctx, certificate.get("file_name") == CERT_FILE.name, "get returns test cert", f"bad get payload {payload}")

        req = urllib.request.Request(f"{BASE_URL}{BASE}/{CERT_FILE.name}/download", headers={"Authorization": f"Bearer {ctx.token}"}, method="GET")
        with urllib.request.urlopen(req, timeout=20) as resp:
            status = resp.status
            headers = dict(resp.headers.items())
            body = resp.read()
        require(ctx, status == 200, f"download test cert ok", f"download returned {status}")
        require(ctx, body.startswith(b"-----BEGIN CERTIFICATE-----"), "download returns PEM bytes", "download body is not certificate")
        lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
        require(ctx, "no-store" in lower_headers.get("cache-control", ""), "download no-store header", f"missing no-store headers={headers}")

        status, payload = call(ctx, "delete test certificate", "DELETE", f"{BASE}/{CERT_FILE.name}")
        require(ctx, status == 200, f"delete test cert ok", f"delete returned {status}: {payload}")
        require(ctx, not CERT_FILE.exists(), "test cert removed from disk", "test cert still exists")

        negative_cases = [
            ("negative-delete missing", "DELETE", f"{BASE}/{CERT_FILE.name}", 404),
            ("negative-download missing", "GET", f"{BASE}/{CERT_FILE.name}/download", 404),
            ("negative-path traversal", "GET", f"{BASE}/..%2Fsecret.key/download", 400),
        ]
        for label, method, path, expected in negative_cases:
            status, payload = call(ctx, label, method, path)
            require(ctx, status in {expected, 404}, f"{label} rejected", f"{label} returned {status}, expected {expected}: {payload}")
    finally:
        _restore(ctx)
