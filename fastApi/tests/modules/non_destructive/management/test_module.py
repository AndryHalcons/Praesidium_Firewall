"""Tests no destructivos de Management."""
from __future__ import annotations

from common.runner import call, request, require as runner_require

BASE = "/api/v1/management"


def check(ctx, condition: bool, message: str) -> None:
    runner_require(ctx, condition, message, message)


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code", detail))
        return str(detail)
    return str(payload)


def run(ctx) -> None:
    ctx.log("=== MANAGEMENT NON-DESTRUCTIVE ===")

    status, payload = call(ctx, "status", "GET", f"{BASE}/status")
    check(ctx, status == 200 and payload.get("module") == "management", "status failed")

    status, payload = call(ctx, "list config", "GET", BASE)
    check(ctx, status == 200 and isinstance(payload.get("config"), dict), "list config failed")
    check(ctx, "table_management_listener" in payload["config"], "missing listener section")
    check(ctx, "table_management_allowed_sources" in payload["config"], "missing allowed sources section")
    check(ctx, "table_management_tls" in payload["config"], "missing tls section")

    status, payload = call(ctx, "get listener", "GET", f"{BASE}/listener")
    check(ctx, status == 200 and payload.get("listener", {}).get("listen_port"), "get listener failed")
    check(ctx, "UUID" not in payload.get("listener", {}), "listener leaked internal UUID")

    status, payload = call(ctx, "get tls", "GET", f"{BASE}/tls")
    check(ctx, status == 200 and payload.get("tls", {}).get("certificate_file"), "get tls failed")
    check(ctx, "UUID" not in payload.get("tls", {}), "tls leaked internal UUID")

    status, payload = call(ctx, "list allowed sources", "GET", f"{BASE}/allowed-sources")
    check(ctx, status == 200 and isinstance(payload.get("allowed_sources"), list), "list allowed sources failed")
    sources = payload["allowed_sources"]
    check(ctx, sources, "expected existing allowed source")
    check(ctx, all("UUID" not in row for row in sources), "allowed sources leaked internal UUID")
    first_id = sources[0]["id"]

    status, payload = call(ctx, "get allowed source", "GET", f"{BASE}/allowed-sources/{first_id}")
    check(ctx, status == 200 and payload.get("allowed_source", {}).get("id") == first_id, "get allowed source failed")

    negatives = [
        ("negative-get missing allowed source", "GET", f"{BASE}/allowed-sources/999999", None, 404),
        ("negative-get invalid id", "GET", f"{BASE}/allowed-sources/bad", None, 422),
    ]
    if ctx.identity.role != "admin":
        negatives.extend([
            ("negative-viewer patch listener", "PATCH", f"{BASE}/listener", {"listen_ip": "0.0.0.0", "listen_port": "443", "server_name": "praesidium.local"}, 403),
            ("negative-viewer patch tls", "PATCH", f"{BASE}/tls", {"certificate_file": "a.pem", "certificate_key": "a.key", "certificate_chain": "a.pem"}, 403),
            ("negative-viewer create allowed source", "POST", f"{BASE}/allowed-sources", {"source_cidr": "203.0.113.0/24", "description": "viewer"}, 403),
            ("negative-viewer patch allowed source", "PATCH", f"{BASE}/allowed-sources/{first_id}", {"description": "viewer"}, 403),
            ("negative-viewer delete allowed source", "DELETE", f"{BASE}/allowed-sources/{first_id}", None, 403),
        ])
    for name, method, path, body, expected in negatives:
        status, payload = call(ctx, name, method, path, body)
        check(ctx, status == expected, f"{name} expected {expected}, got {status}: {_detail(payload)}")

    if ctx.identity.role == "admin":
        admin_negatives = [
            ("negative-invalid listener ip", "PATCH", f"{BASE}/listener", {"listen_ip": "not-ip", "listen_port": "443", "server_name": "praesidium.local"}, 422),
            ("negative-invalid listener port", "PATCH", f"{BASE}/listener", {"listen_ip": "0.0.0.0", "listen_port": "70000", "server_name": "praesidium.local"}, 422),
            ("negative-invalid listener server", "PATCH", f"{BASE}/listener", {"listen_ip": "0.0.0.0", "listen_port": "443", "server_name": "bad name"}, 422),
            ("negative-invalid tls file", "PATCH", f"{BASE}/tls", {"certificate_file": "bad name.pem", "certificate_key": "k.key", "certificate_chain": "c.pem"}, 422),
            ("negative-invalid cidr", "POST", f"{BASE}/allowed-sources", {"source_cidr": "999.999.999.999/24", "description": "bad"}, 422),
            ("negative-empty patch", "PATCH", f"{BASE}/allowed-sources/{first_id}", {}, 422),
        ]
        for name, method, path, body, expected in admin_negatives:
            status, payload = call(ctx, name, method, path, body)
            check(ctx, status == expected, f"{name} expected {expected}, got {status}: {_detail(payload)}")
