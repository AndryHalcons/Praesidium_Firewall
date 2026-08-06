"""Tests no destructivos de Services."""
from __future__ import annotations

from common.runner import call, request, require

BASE = "/api/v1/services"


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)


def _expect_role(ctx, status: int, admin_expected: int, viewer_expected: int, label: str) -> None:
    expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
    require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}: {status}")


def run(ctx) -> None:
    ctx.log("=== SERVICES NON-DESTRUCTIVE ===")

    for label, path in [
        ("status", f"{BASE}/status"),
        ("list config", BASE),
        ("list catalog", f"{BASE}/catalog"),
        ("list rows", f"{BASE}/rows"),
        ("runtime status", f"{BASE}/runtime"),
        ("get dnsmasq", f"{BASE}/dnsmasq"),
        ("get forwarding ipv4", f"{BASE}/forwarding_ipv4"),
    ]:
        status, payload = call(ctx, label, "GET", path)
        require(ctx, status == 200, f"{label} readable", f"{label} failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-missing service", "GET", f"{BASE}/notreal")
    require(ctx, status == 404, "missing service rejected", f"missing service returned {status}: {_detail(payload)}")

    mutation_cases = [
        ("update missing service", f"{BASE}/notreal", {"desired_enabled": "true"}, 404),
        ("update invalid desired", f"{BASE}/dnsmasq", {"desired_enabled": "maybe"}, 422),
        ("update monitor-only service", f"{BASE}/apache2", {"desired_enabled": "false"}, 409),
        ("update malformed payload", f"{BASE}/dnsmasq", {"rule": {"desired_enabled": "true"}}, 422),
    ]
    for label, path, body, admin_expected in mutation_cases:
        status, payload = call(ctx, f"negative-{label}", "PATCH", path, body)
        _expect_role(ctx, status, admin_expected, 403, label)

    for label, method, path in [
        ("post disabled", "POST", BASE),
        ("delete disabled", "DELETE", f"{BASE}/dnsmasq"),
    ]:
        status, payload = call(ctx, f"negative-{label}", method, path)
        require(ctx, status in {404, 405}, f"{label} rejected", f"{label} returned {status}: {_detail(payload)}")

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    expected = {
        f"{BASE}/status",
        BASE,
        f"{BASE}/catalog",
        f"{BASE}/rows",
        f"{BASE}/runtime",
        f"{BASE}/{{service_name}}",
    }
    missing = sorted(path for path in expected if path not in paths)
    require(ctx, not missing, "services OpenAPI endpoints present", f"missing services OpenAPI endpoints: {missing}")
    forbidden = [p for p in paths if p.startswith(BASE) and any(part in p for part in ["forms", "structure", "content", "table_content", "table_structure"])]
    require(ctx, not forbidden, "services exposes no WebGUI helper routes", f"forbidden services helper routes exposed: {forbidden}")
