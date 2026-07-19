"""Tests no destructivos de System Logging."""
from __future__ import annotations

from common.runner import call, request, require

BASE = "/api/v1/system-logging"
SECTIONS = {
    "journald": {"uuid", "system_max_use", "system_keep_free", "runtime_max_use", "max_retention_sec", "compress"},
    "system-logs": {"uuid", "enabled", "rotation", "rotate", "maxsize", "compress", "delaycompress"},
    "nftables-logs": {"uuid", "enabled", "size", "rotate", "compress", "delaycompress"},
}


def run(ctx) -> None:
    ctx.log("=== SYSTEM LOGGING NON-DESTRUCTIVE ===")

    status, payload = call(ctx, "status", "GET", f"{BASE}/status")
    require(ctx, status == 200 and payload.get("module") == "system_logging", "status readable", f"status failed {status}: {payload}")

    status, payload = call(ctx, "list config", "GET", BASE)
    config = payload.get("config", {}) if isinstance(payload, dict) else {}
    require(ctx, status == 200 and set(config) == {"journald", "system_logs", "nftables_logs"}, "config sections readable", f"config failed {status}: {payload}")
    require(ctx, "UUID" not in config, "obsolete root UUID absent", "obsolete root UUID exposed")

    response_keys = {"journald": "journald", "system-logs": "system_logs", "nftables-logs": "nftables_logs"}
    for route, expected_fields in SECTIONS.items():
        status, payload = call(ctx, f"get {route}", "GET", f"{BASE}/{route}")
        section = payload.get(response_keys[route], {}) if isinstance(payload, dict) else {}
        require(ctx, status == 200 and set(section) == expected_fields, f"{route} fields readable", f"{route} failed {status}: {payload}")
        require(ctx, isinstance(section.get("uuid"), str) and bool(section["uuid"].strip()), f"{route} static uuid readable", f"{route} static uuid missing")

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "OpenAPI readable", f"OpenAPI failed {status}")
    paths = openapi.get("paths", {}) if isinstance(openapi, dict) else {}
    expected_paths = {
        BASE: {"get"},
        f"{BASE}/status": {"get"},
        f"{BASE}/journald": {"get", "patch"},
        f"{BASE}/system-logs": {"get", "patch"},
        f"{BASE}/nftables-logs": {"get", "patch"},
    }
    for path, methods in expected_paths.items():
        require(ctx, path in paths and methods <= set(paths[path]), f"OpenAPI {path} methods present", f"OpenAPI contract missing for {path}")
    require(ctx, not any(path.startswith("/api/v1/system/") for path in paths), "old System routes absent", "old System routes still exposed")
    forbidden = [f"{BASE}/forms", f"{BASE}/structure", f"{BASE}/content"]
    require(ctx, not any(path in paths for path in forbidden), "WebGUI helper routes absent", "forbidden helper route exposed")
