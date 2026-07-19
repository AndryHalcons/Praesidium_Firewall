"""Tests no destructivos del módulo bpfilter FastAPI."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from common.runner import BASE_URL, call, request, require

BPFILTER = Path("/var/lib/praesidium/candidate/rules_bpfilter_human_viewer.json")
EXPECTED_HOOKS = [
    {"hook": "xdp", "value": "BF_HOOK_XDP"},
    {"hook": "tc-ingress", "value": "BF_HOOK_TC_INGRESS"},
    {"hook": "tc-egress", "value": "BF_HOOK_TC_EGRESS"},
]
REQUIRED_OPENAPI_PATHS = {
    "/api/v1/bpfilter/status",
    "/api/v1/bpfilter/hooks",
    "/api/v1/bpfilter",
    "/api/v1/bpfilter/{hook}",
    "/api/v1/bpfilter/{hook}/{rule_id}",
}
FORBIDDEN_PATH_FRAGMENTS = ("forms", "structure", "content")


def _openapi() -> dict:
    # ES: Lee OpenAPI para comprobar contrato visible al usuario.
    # EN: Read OpenAPI to verify the contract visible to the user.
    with urllib.request.urlopen(BASE_URL + "/openapi.json", timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def run(ctx) -> None:
    ctx.log("=== BPFILTER NON-DESTRUCTIVE ===")
    before = BPFILTER.read_text(encoding="utf-8")

    status, payload = call(ctx, "status", "GET", "/api/v1/bpfilter/status")
    require(ctx, status == 200 and payload.get("module") == "bpfilter", "status returns bpfilter module", "status failed")

    status, payload = call(ctx, "hooks", "GET", "/api/v1/bpfilter/hooks")
    require(ctx, status == 200 and payload.get("hooks") == EXPECTED_HOOKS, "hooks endpoint exposes usable hooks", f"hooks endpoint unexpected {payload}")

    status, payload = request("GET", "/api/v1/bpfilter", token=ctx.token)
    ctx.log("REQUEST list bpfilter: GET /api/v1/bpfilter")
    ctx.log(f"RESPONSE {status}: <config omitted>")
    require(ctx, status == 200 and isinstance(payload.get("config", {}).get("bpfilter"), list), "list all returns bpfilter list", "list all failed")

    for hook in ("xdp", "tc-ingress", "tc-egress"):
        status, payload = call(ctx, f"list hook {hook}", "GET", f"/api/v1/bpfilter/{hook}")
        require(ctx, status == 200 and isinstance(payload.get("rules"), list), f"hook {hook} lists rules", f"hook {hook} failed")

    status, payload = call(ctx, "negative-invalid hook", "GET", "/api/v1/bpfilter/not-a-hook")
    require(ctx, status == 422, "invalid hook rejected", "invalid hook not rejected")

    status, payload = call(ctx, "negative-viewer/admin mutation contract", "POST", "/api/v1/bpfilter/xdp", {"rule": {"interface": "ens19", "action": "DROP", "enable": "true", "l3_protocol": "IPv4", "l4_protocol": "TCP", "destination": "8.8.8.8"}})
    if ctx.identity.role == "viewer":
        require(ctx, status == 403, "viewer cannot mutate bpfilter", "viewer bpfilter mutation was not forbidden")
    else:
        require(ctx, status in {200, 422}, "admin bpfilter mutation route is wired", f"admin mutation unexpected {status}")
        BPFILTER.write_text(before, encoding="utf-8")
        BPFILTER.chmod(0o664)

    spec = _openapi()
    paths = [path for path in spec.get("paths", {}) if "/api/v1/bpfilter" in path]
    require(ctx, not any(any(fragment in path for fragment in FORBIDDEN_PATH_FRAGMENTS) for path in paths), "OpenAPI has no forbidden bpfilter paths", f"OpenAPI forbidden bpfilter paths present: {paths}")
    for required_path in sorted(REQUIRED_OPENAPI_PATHS):
        require(ctx, required_path in paths, f"OpenAPI includes {required_path}", f"OpenAPI missing {required_path}")

    after = BPFILTER.read_text(encoding="utf-8")
    require(ctx, after == before, "bpfilter candidate unchanged by non-destructive tests", "bpfilter candidate changed")
