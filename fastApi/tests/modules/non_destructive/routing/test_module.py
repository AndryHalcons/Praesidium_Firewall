"""Tests no destructivos del módulo Routing."""
from __future__ import annotations

from common.runner import call, request, require

BASE = "/api/v1/routing"


def run(ctx) -> None:
    ctx.log("=== ROUTING NON-DESTRUCTIVE ===")

    status, payload = call(ctx, "routing status", "GET", f"{BASE}/status")
    require(ctx, status == 200 and payload.get("module") == "routing", "routing status readable", f"status failed {status}: {payload}")

    status, payload = call(ctx, "read routing snapshot", "GET", BASE)
    require(ctx, status == 200, "routing snapshot readable", f"read failed {status}: {payload}")
    require(ctx, isinstance(payload.get("routes"), list), "routes list returned", f"routes not list: {payload}")
    require(ctx, isinstance(payload.get("rules"), list), "rules list returned", f"rules not list: {payload}")
    require(ctx, isinstance(payload.get("has_snapshot"), bool), "has_snapshot bool returned", f"has_snapshot bad: {payload}")

    status, payload = call(ctx, "reload routing permission", "POST", f"{BASE}/reload")
    if ctx.identity.role == "viewer":
        require(ctx, status == 403, "viewer cannot reload routing", f"viewer reload returned {status}: {payload}")
    else:
        require(ctx, status == 200 and payload.get("status") == "ok", "admin reload routing works", f"admin reload failed {status}: {payload}")
        require(ctx, isinstance(payload.get("routes"), list), "reload returns routes list", f"routes not list after reload: {payload}")
        require(ctx, isinstance(payload.get("rules"), list), "reload returns rules list", f"rules not list after reload: {payload}")

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    expected = {f"{BASE}/status", BASE, f"{BASE}/reload"}
    missing = sorted(path for path in expected if path not in paths)
    require(ctx, not missing, "routing OpenAPI endpoints present", f"missing routing OpenAPI endpoints: {missing}")
