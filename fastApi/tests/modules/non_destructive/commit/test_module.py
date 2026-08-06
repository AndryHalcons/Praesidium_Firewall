"""Tests no destructivos de Commit."""
from __future__ import annotations

from common.runner import call, request, require

BASE = "/api/v1/commit"


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)


def run(ctx) -> None:
    ctx.log("=== COMMIT NON-DESTRUCTIVE ===")
    for label, method, path in [
        ("status", "GET", f"{BASE}/status"),
        ("user", "GET", f"{BASE}/user"),
        ("preview", "GET", f"{BASE}/preview"),
        ("config candidate", "GET", f"{BASE}/config?mode=candidate"),
        ("config running", "GET", f"{BASE}/config?mode=running"),
    ]:
        status, payload = call(ctx, label, method, path)
        require(ctx, status == 200, f"{label} readable", f"{label} failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "negative-config invalid mode", "GET", f"{BASE}/config?mode=bad")
    require(ctx, status == 422, "invalid config mode rejected", f"invalid mode returned {status}: {payload}")

    status, payload = call(ctx, "apply permission/sudo", "POST", f"{BASE}/apply")
    if ctx.identity.role == "viewer":
        require(ctx, status == 403, "viewer cannot apply", f"viewer apply returned {status}: {_detail(payload)}")
    else:
        require(ctx, status == 200, "admin apply endpoint reached", f"admin apply unexpected {status}: {_detail(payload)}")
        require(ctx, isinstance(payload, dict) and "commit_result" in payload, "admin apply returns commit_result", f"bad apply payload: {payload}")

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    expected = {f"{BASE}/status", f"{BASE}/user", f"{BASE}/preview", f"{BASE}/config", f"{BASE}/apply"}
    missing = sorted(path for path in expected if path not in paths)
    require(ctx, not missing, "commit OpenAPI endpoints present", f"missing commit OpenAPI endpoints: {missing}")
