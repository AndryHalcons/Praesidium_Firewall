"""Tests no destructivos de las tres secciones WireGuard. / Non-destructive tests for all WireGuard sections."""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from common.runner import BASE_URL, call, request, require

BASE = "/api/v1/wireguard"
SECTIONS = ("site_to_site", "remote_access", "remote_clients")


def _detail(payload: Any) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)


def _expect_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}")


def _raw_get(path: str, token: str) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(BASE_URL + path, headers={"Authorization": f"Bearer {token}"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read(), {key.lower(): value for key, value in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {key.lower(): value for key, value in exc.headers.items()}


def run(ctx) -> None:
    ctx.log("=== WIREGUARD NON-DESTRUCTIVE: THREE SECTIONS ===")

    status, payload = call(ctx, "status", "GET", f"{BASE}/status")
    require(ctx, status == 200, "wireguard status readable", f"wireguard status failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "list config", "GET", BASE)
    config = payload.get("config", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and all(isinstance(config.get(section), dict) for section in SECTIONS), "full config exposes three dictionary sections", f"invalid full config contract {status}: {payload}")

    for section, path in (
        ("site_to_site", f"{BASE}/site-to-site"),
        ("remote_access", f"{BASE}/remote-access"),
        ("remote_clients", f"{BASE}/remote-clients"),
    ):
        status, payload = call(ctx, f"list {section}", "GET", path)
        require(ctx, status == 200 and payload.get("section") == section and isinstance(payload.get("entries"), dict), f"{section} list contract valid", f"{section} list contract failed {status}: {payload}")

    missing_paths = [
        ("site UUID", f"{BASE}/site-to-site/wgsite-999-19700101000000000-0000", False),
        ("server UUID", f"{BASE}/remote-access/wgserv-999-19700101000000000-0000", False),
        ("client UUID", f"{BASE}/remote-clients/wgclient-999-19700101000000000-0000", False),
        ("client config UUID", f"{BASE}/remote-clients/wgclient-999-19700101000000000-0000/config", True),
        ("client QR UUID", f"{BASE}/remote-clients/wgclient-999-19700101000000000-0000/qr", True),
        ("client bundle UUID", f"{BASE}/remote-clients/wgclient-999-19700101000000000-0000/bundle", True),
    ]
    for label, path, admin_only in missing_paths:
        if admin_only:
            status, _, _ = _raw_get(path, ctx.token)
        else:
            status, _ = call(ctx, f"negative-missing {label}", "GET", path)
        _expect_role(ctx, status, 404, 403 if admin_only else 404, f"missing {label}")

    invalid_cases = [
        ("create invalid section", "POST", f"{BASE}/notreal", {"rule": {"enabled": "false"}}, 404, 404),
        ("create invalid site", "POST", f"{BASE}/site-to-site", {"rule": {"name": "bad name", "enabled": "maybe"}}, 422, 403),
        ("create invalid server", "POST", f"{BASE}/remote-access", {"rule": {"name": "bad name", "enabled": "maybe"}}, 422, 403),
        ("create invalid client", "POST", f"{BASE}/remote-clients", {"rule": {"name": "bad name", "enabled": "maybe"}}, 422, 403),
        ("patch missing site UUID", "PATCH", f"{BASE}/site-to-site/wgsite-999-19700101000000000-0000", {"rule": {"name": "missing-site"}}, 404, 403),
        ("patch missing server UUID", "PATCH", f"{BASE}/remote-access/wgserv-999-19700101000000000-0000", {"rule": {"name": "missing-server"}}, 404, 403),
        ("patch missing client UUID", "PATCH", f"{BASE}/remote-clients/wgclient-999-19700101000000000-0000", {"rule": {"name": "missing-client"}}, 404, 403),
        ("delete missing site UUID", "DELETE", f"{BASE}/site-to-site/wgsite-999-19700101000000000-0000", None, 404, 403),
        ("delete missing server UUID", "DELETE", f"{BASE}/remote-access/wgserv-999-19700101000000000-0000", None, 404, 403),
        ("delete missing client UUID", "DELETE", f"{BASE}/remote-clients/wgclient-999-19700101000000000-0000", None, 404, 403),
    ]
    for label, method, path, body, admin_expected, viewer_expected in invalid_cases:
        status, _ = call(ctx, f"negative-{label}", method, path, body)
        _expect_role(ctx, status, admin_expected, viewer_expected, label)

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    expected = {
        f"{BASE}/status", BASE,
        f"{BASE}/site-to-site", f"{BASE}/site-to-site/{{uuid}}",
        f"{BASE}/remote-access", f"{BASE}/remote-access/{{uuid}}",
        f"{BASE}/remote-clients", f"{BASE}/remote-clients/{{uuid}}",
        f"{BASE}/remote-clients/{{uuid}}/config", f"{BASE}/remote-clients/{{uuid}}/qr", f"{BASE}/remote-clients/{{uuid}}/bundle",
    }
    missing = sorted(path for path in expected if path not in paths)
    require(ctx, not missing, "wireguard OpenAPI UUID endpoints present", f"missing wireguard OpenAPI endpoints: {missing}")
    legacy = sorted(path for path in paths if path.startswith(BASE) and "{name}" in path)
    require(ctx, not legacy, "legacy WireGuard name routes absent", f"legacy WireGuard name routes exposed: {legacy}")

    schemas = openapi.get("components", {}).get("schemas", {}) if isinstance(openapi, dict) else {}
    mutation_props = schemas.get("WireGuardMutationResponse", {}).get("properties", {})
    require(ctx, all(field in mutation_props for field in ("id", "UUID", "name")), "identity fields present in mutation schema for all sections", "missing id/UUID/name in WireGuardMutationResponse")
    entry_props = schemas.get("WireGuardEntryResponse", {}).get("properties", {})
    require(ctx, all(field in entry_props for field in ("section", "name", "entry")), "entry response schema present", f"invalid WireGuardEntryResponse schema: {entry_props}")

    forbidden = [path for path in paths if path.startswith(BASE) and any(part in path for part in ("forms", "structure", "content", "table_content", "table_structure"))]
    require(ctx, not forbidden, "wireguard exposes no WebGUI helper routes", f"forbidden wireguard helper routes exposed: {forbidden}")
