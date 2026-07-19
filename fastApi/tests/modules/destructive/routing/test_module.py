"""Tests destructivos del módulo Routing."""
from __future__ import annotations

from pathlib import Path

from common.runner import call, require

BASE = "/api/v1/routing"
STATE_FILE = Path("/var/lib/praesidium/state/routes/routes.json")


def run(ctx) -> None:
    ctx.log("=== ROUTING DESTRUCTIVE ===")
    before = STATE_FILE.read_text(encoding="utf-8") if STATE_FILE.exists() else None
    try:
        status, payload = call(ctx, "reload routing snapshot", "POST", f"{BASE}/reload")
        if ctx.identity.role == "viewer":
            require(ctx, status == 403, "viewer cannot reload routing", f"viewer reload returned {status}: {payload}")
            return
        require(ctx, status == 200 and payload.get("status") == "ok", "admin reload routing succeeds", f"reload failed {status}: {payload}")
        require(ctx, STATE_FILE.exists(), "routing state file exists", "routing state file missing")
        require(ctx, isinstance(payload.get("routes"), list), "reload returns routes", f"bad routes: {payload}")
        require(ctx, isinstance(payload.get("rules"), list), "reload returns rules", f"bad rules: {payload}")

        status, read_payload = call(ctx, "read after reload", "GET", BASE)
        require(ctx, status == 200 and read_payload.get("has_snapshot") is True, "read after reload has snapshot", f"read failed {status}: {read_payload}")
    finally:
        if before is not None:
            STATE_FILE.write_text(before, encoding="utf-8")
            ctx.log("RESTORE routing state snapshot restored")
        elif STATE_FILE.exists():
            STATE_FILE.unlink()
            ctx.log("RESTORE routing state snapshot removed")
