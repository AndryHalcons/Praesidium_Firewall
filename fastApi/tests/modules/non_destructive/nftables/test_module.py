"""Tests no destructivos del módulo nftables FastAPI."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from common.runner import BASE_URL, call, request, require

NFTABLES = Path("/var/lib/praesidium/candidate/rules_nftables_human_viewer.json")
TABLES_CHAINS = Path("/var/lib/praesidium/candidate/nftables_tables_chains.json")
EXPECTED_CHAINS = [("filter", "input"), ("filter", "output"), ("filter", "FORWARDING"), ("nat", "POSTROUTING"), ("nat", "PREROUTING")]
REQUIRED_OPENAPI_PATHS = {
    "/api/v1/nftables/status",
    "/api/v1/nftables/chains",
    "/api/v1/nftables/tables",
    "/api/v1/nftables/tables/{table}",
    "/api/v1/nftables/tables/{table}/chains",
    "/api/v1/nftables/tables/{table}/chains/{chain}",
    "/api/v1/nftables",
    "/api/v1/nftables/{table}/{chain}",
    "/api/v1/nftables/{table}/{chain}/{rule_id}",
}
FORBIDDEN_PATH_FRAGMENTS = ("forms", "structure", "content")


def _openapi() -> dict:
    # ES: Lee OpenAPI para validar que la API pública no expone helpers WebGUI.
    # EN: Read OpenAPI to verify public API does not expose WebGUI helpers.
    with urllib.request.urlopen(BASE_URL + "/openapi.json", timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def run(ctx) -> None:
    ctx.log("=== NFTABLES NON-DESTRUCTIVE ===")
    before = NFTABLES.read_text(encoding="utf-8")
    before_tables_chains = TABLES_CHAINS.read_text(encoding="utf-8")

    status, payload = call(ctx, "status", "GET", "/api/v1/nftables/status")
    require(ctx, status == 200 and payload.get("module") == "nftables", "status returns nftables module", "status failed")

    status, payload = call(ctx, "chains", "GET", "/api/v1/nftables/chains")
    chains = [(item.get("table"), item.get("chain")) for item in payload.get("chains", [])] if isinstance(payload, dict) else []
    require(ctx, status == 200 and chains == EXPECTED_CHAINS, "chains endpoint exposes usable table/chain pairs", f"chains endpoint unexpected {payload}")


    status, payload = call(ctx, "list tables", "GET", "/api/v1/nftables/tables")
    tables = [item.get("name") for item in payload.get("tables", [])] if isinstance(payload, dict) else []
    require(ctx, status == 200 and "filter" in tables and "nat" in tables, "tables endpoint lists declared tables", f"tables endpoint unexpected {payload}")

    status, payload = call(ctx, "get filter table", "GET", "/api/v1/nftables/tables/filter")
    require(ctx, status == 200 and payload.get("table", {}).get("family") == "inet", "get table returns inet table", f"get table failed {payload}")

    status, payload = call(ctx, "list filter chains", "GET", "/api/v1/nftables/tables/filter/chains")
    filter_chains = [item.get("name") for item in payload.get("chains", [])] if isinstance(payload, dict) else []
    require(ctx, status == 200 and {"input", "output", "FORWARDING"}.issubset(set(filter_chains)), "table chains endpoint lists filter chains", f"filter chains unexpected {payload}")

    status, payload = call(ctx, "get input chain", "GET", "/api/v1/nftables/tables/filter/chains/input")
    require(ctx, status == 200 and payload.get("chain", {}).get("family") == "inet", "get chain returns inet chain", f"get chain failed {payload}")

    status, payload = call(ctx, "negative-missing table", "GET", "/api/v1/nftables/tables/notreal")
    require(ctx, status == 404, "missing table rejected", "missing table not rejected")

    status, payload = call(ctx, "negative-missing chain", "GET", "/api/v1/nftables/tables/filter/chains/notreal")
    require(ctx, status == 404, "missing chain rejected", "missing chain not rejected")

    status, payload = request("GET", "/api/v1/nftables", token=ctx.token)
    ctx.log("REQUEST list nftables: GET /api/v1/nftables")
    ctx.log(f"RESPONSE {status}: <config omitted>")
    require(ctx, status == 200 and isinstance(payload.get("config", {}).get("nftables"), list), "list all returns nftables list", "list all failed")

    for table, chain in EXPECTED_CHAINS:
        status, payload = call(ctx, f"list table chain {table}/{chain}", "GET", f"/api/v1/nftables/{table}/{chain}")
        require(ctx, status == 200 and isinstance(payload.get("rules"), list), f"table/chain {table}/{chain} lists rules", f"table/chain {table}/{chain} failed")

    status, payload = call(ctx, "negative-invalid table chain", "GET", "/api/v1/nftables/filter/PREROUTING")
    require(ctx, status == 404, "invalid table/chain rejected", "invalid table/chain not rejected")

    status, payload = call(ctx, "negative-viewer/admin mutation contract", "POST", "/api/v1/nftables/filter/FORWARDING", {"rule": {"action": "accept", "enable": "true", "ip.protocol": "tcp", "dport": "443"}})
    if ctx.identity.role == "viewer":
        require(ctx, status == 403, "viewer cannot mutate nftables", "viewer nftables mutation was not forbidden")
    else:
        require(ctx, status in {200, 422}, "admin nftables mutation route is wired", f"admin mutation unexpected {status}")
        NFTABLES.write_text(before, encoding="utf-8")
        NFTABLES.chmod(0o664)


    status, payload = call(ctx, "negative-viewer/admin table mutation contract", "POST", "/api/v1/nftables/tables", {"table": {"name": "tmp_nft_nd_table", "family": "inet"}})
    if ctx.identity.role == "viewer":
        require(ctx, status == 403, "viewer cannot mutate nftables tables", "viewer nftables table mutation was not forbidden")
    else:
        require(ctx, status in {200, 409, 422}, "admin nftables table mutation route is wired", f"admin table mutation unexpected {status}")
        TABLES_CHAINS.write_text(before_tables_chains, encoding="utf-8")
        TABLES_CHAINS.chmod(0o664)

    spec = _openapi()
    paths = [path for path in spec.get("paths", {}) if "/api/v1/nftables" in path]
    require(ctx, not any(any(fragment in path for fragment in FORBIDDEN_PATH_FRAGMENTS) for path in paths), "OpenAPI has no forbidden nftables paths", f"OpenAPI forbidden nftables paths present: {paths}")
    for required_path in sorted(REQUIRED_OPENAPI_PATHS):
        require(ctx, required_path in paths, f"OpenAPI includes {required_path}", f"OpenAPI missing {required_path}")

    methods = {path: set(spec.get("paths", {}).get(path, {}).keys()) for path in paths}
    require(ctx, "patch" not in methods.get("/api/v1/nftables/tables/{table}", set()), "OpenAPI has no table PATCH", "OpenAPI exposes table PATCH")
    require(ctx, "patch" not in methods.get("/api/v1/nftables/tables/{table}/chains/{chain}", set()), "OpenAPI has no chain PATCH", "OpenAPI exposes chain PATCH")

    after = NFTABLES.read_text(encoding="utf-8")
    after_tables_chains = TABLES_CHAINS.read_text(encoding="utf-8")
    require(ctx, after == before, "nftables candidate unchanged by non-destructive tests", "nftables candidate changed")
    require(ctx, after_tables_chains == before_tables_chains, "nftables tables/chains candidate unchanged by non-destructive tests", "nftables tables/chains candidate changed")
