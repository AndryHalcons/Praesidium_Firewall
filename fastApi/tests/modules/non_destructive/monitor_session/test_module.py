"""Tests no destructivos de Monitor Session."""
from __future__ import annotations

from common.runner import call, request, require

BASE = "/api/v1/monitor-session"


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)


def run(ctx) -> None:
    ctx.log("=== MONITOR SESSION NON-DESTRUCTIVE ===")
    for label, method, path in [
        ("status", "GET", f"{BASE}/status"),
        ("columns", "GET", f"{BASE}/columns"),
        ("sessions", "GET", f"{BASE}/sessions"),
    ]:
        status, payload = call(ctx, label, method, path)
        require(ctx, status == 200, f"{label} readable", f"{label} failed {status}: {_detail(payload)}")

    status, payload = call(ctx, "run list tcp", "POST", f"{BASE}/run", {"action": "-L", "arguments": "-p tcp"})
    require(ctx, status == 200, "run -L -p tcp allowed", f"run list tcp failed {status}: {_detail(payload)}")
    require(ctx, payload.get("action") == "-L", "run echoes action", f"bad run payload: {payload}")
    require(ctx, payload.get("has_snapshot") is True, "run query created snapshot", f"no snapshot after run: {payload}")

    status, payload = call(ctx, "reject shell separator", "POST", f"{BASE}/run", {"action": "-L", "arguments": "-p tcp ; rm -rf"})
    require(ctx, status == 422 and "MONITOR_SESSION_UNSAFE_ARGUMENT" in _detail(payload), "shell separator rejected", f"unsafe separator accepted: {status} {payload}")

    status, payload = call(ctx, "reject command word", "POST", f"{BASE}/run", {"action": "-L", "arguments": ["rm"]})
    require(ctx, status == 422 and "MONITOR_SESSION_COMMAND_WORD_FORBIDDEN" in _detail(payload), "command word rejected", f"command word accepted: {status} {payload}")

    status, payload = call(ctx, "reject output override", "POST", f"{BASE}/run", {"action": "-L", "arguments": ["-o", "xml"]})
    require(ctx, status == 422 and "MONITOR_SESSION_OUTPUT_FLAG_FORBIDDEN" in _detail(payload), "output override rejected", f"output override accepted: {status} {payload}")

    status, payload = call(ctx, "reject unsupported action", "POST", f"{BASE}/run", {"action": "-I", "arguments": "conntrack"})
    require(ctx, status == 422 and "MONITOR_SESSION_ACTION_NOT_ALLOWED" in _detail(payload), "unsupported action rejected", f"unsupported action accepted: {status} {payload}")

    if ctx.identity.role == "viewer":
        status, payload = call(ctx, "viewer mutation guard", "POST", f"{BASE}/run", {"action": "-F", "arguments": "conntrack"})
        require(ctx, status == 403, "viewer cannot run destructive action", f"viewer destructive returned {status}: {_detail(payload)}")
    else:
        ctx.log("SKIP admin destructive action in non-destructive test")

    status, payload = call(ctx, "refresh admin", "POST", f"{BASE}/refresh")
    if ctx.identity.role == "viewer":
        require(ctx, status == 403, "viewer cannot refresh", f"viewer refresh returned {status}: {_detail(payload)}")
    else:
        require(ctx, status == 200, "admin refresh succeeds through sudoers", f"admin refresh unexpected {status}: {_detail(payload)}")

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    expected = {f"{BASE}/status", f"{BASE}/columns", f"{BASE}/sessions", f"{BASE}/run", f"{BASE}/refresh"}
    missing = sorted(path for path in expected if path not in paths)
    require(ctx, not missing, "monitor-session OpenAPI endpoints present", f"missing monitor-session OpenAPI endpoints: {missing}")
    forbidden = [p for p in paths if p.startswith(BASE) and any(part in p for part in ["forms", "structure", "content", "table_content", "table_structure"])]
    require(ctx, not forbidden, "monitor-session exposes no WebGUI helper routes", f"forbidden helper routes exposed: {forbidden}")
