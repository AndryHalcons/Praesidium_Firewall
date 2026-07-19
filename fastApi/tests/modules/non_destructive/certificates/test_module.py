"""Tests no destructivos de Certificates."""
from __future__ import annotations

from common.runner import call, request, require

BASE = "/api/v1/certificates"


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)


def run(ctx) -> None:
    ctx.log("=== CERTIFICATES NON-DESTRUCTIVE ===")

    for label, method, path in [
        ("status", "GET", f"{BASE}/status"),
        ("list certificates", "GET", BASE),
    ]:
        status, payload = call(ctx, label, method, path)
        require(ctx, status == 200, f"{label} readable", f"{label} failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-missing certificate", "GET", f"{BASE}/notreal.pem")
    require(ctx, status == 404, "missing certificate rejected", f"missing certificate returned {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-bad file name", "GET", f"{BASE}/..%2Fsecret.key")
    require(ctx, status in {400, 404}, "bad file name rejected", f"bad file name returned {status}: {_detail(payload)}")

    mutation_cases = [
        ("negative-download missing admin only", "GET", f"{BASE}/notreal.pem/download", None, 404, 403),
        ("negative-delete missing admin only", "DELETE", f"{BASE}/notreal.pem", None, 404, 403),
    ]
    for label, method, path, body, admin_expected, viewer_expected in mutation_cases:
        status, payload = call(ctx, label, method, path, body)
        expected = admin_expected if ctx.identity.role == "admin" else viewer_expected
        require(ctx, status == expected, f"{label} returned expected {expected}", f"{label} returned {status}, expected {expected}: {_detail(payload)}")

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    expected = {
        f"{BASE}/status",
        BASE,
        f"{BASE}/{{file_name}}",
        f"{BASE}/{{file_name}}/download",
    }
    missing = sorted(path for path in expected if path not in paths)
    require(ctx, not missing, "certificates OpenAPI endpoints present", f"missing certificates OpenAPI endpoints: {missing}")
    forbidden = [p for p in paths if p.startswith(BASE) and any(part in p for part in ["forms", "structure", "content", "table_content", "table_structure"])]
    require(ctx, not forbidden, "certificates exposes no WebGUI helper routes", f"forbidden certificates helper routes exposed: {forbidden}")
