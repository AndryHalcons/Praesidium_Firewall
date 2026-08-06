"""Tests no destructivos del módulo interfaces FastAPI."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from common.runner import BASE_URL, call, request, require

INTERFACES = Path("/var/lib/praesidium/candidate/interfaces.json")
EXPECTED_SECTIONS = {"ethernets", "bridges", "bonds", "vlans", "wifis"}
FORBIDDEN_PATH_FRAGMENTS = ("forms", "structure", "content")
REQUIRED_OPENAPI_PATHS = {
    "/api/v1/interfaces/status",
    "/api/v1/interfaces",
    "/api/v1/interfaces/scan",
    "/api/v1/interfaces/section/{section}",
    "/api/v1/interfaces/ethernets",
    "/api/v1/interfaces/ethernets/{uuid}",
    "/api/v1/interfaces/bridges",
    "/api/v1/interfaces/bridges/{uuid}",
    "/api/v1/interfaces/bonds",
    "/api/v1/interfaces/bonds/{uuid}",
    "/api/v1/interfaces/vlans",
    "/api/v1/interfaces/vlans/{uuid}",
    "/api/v1/interfaces/wifis",
    "/api/v1/interfaces/wifis/{uuid}",
}
EXPECTED_COLLECTION_METHODS = {"get", "post"}
EXPECTED_ENTRY_METHODS = {"get", "post", "patch", "delete"}


def _openapi() -> dict:
    with urllib.request.urlopen(BASE_URL + "/openapi.json", timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _restore_candidate(content: str) -> None:
    INTERFACES.write_text(content, encoding="utf-8")
    INTERFACES.chmod(0o664)


def run(ctx) -> None:
    ctx.log("=== INTERFACES NON-DESTRUCTIVE ===")

    before = INTERFACES.read_text(encoding="utf-8")

    status, payload = call(ctx, "status", "GET", "/api/v1/interfaces/status")
    require(ctx, status == 200 and payload.get("module") == "interfaces", "status returns interfaces module", "status failed")

    # ES: Usamos request directo para no volcar config completa en reportes.
    # EN: Use direct request so the full config is not dumped into reports.
    status, payload = request("GET", "/api/v1/interfaces", token=ctx.token)
    ctx.log("REQUEST list all interfaces: GET /api/v1/interfaces")
    ctx.log(f"RESPONSE {status}: <config omitted>")
    require(ctx, status == 200 and isinstance(payload.get("config"), dict), "list all returns config", "list all failed")
    network = payload.get("config", {}).get("network", {})
    require(ctx, EXPECTED_SECTIONS.issubset(set(network.keys())), "list all includes real interface sections", "list all missing sections")

    for section in sorted(EXPECTED_SECTIONS):
        status, payload = call(ctx, f"list section generic {section}", "GET", f"/api/v1/interfaces/section/{section}")
        require(ctx, status == 200 and payload.get("section") == section and isinstance(payload.get("entries"), dict), f"generic section {section} lists entries", f"generic section {section} failed")
        status, payload = call(ctx, f"list section direct {section}", "GET", f"/api/v1/interfaces/{section}")
        require(ctx, status == 200 and payload.get("section") == section and isinstance(payload.get("entries"), dict), f"direct section {section} lists entries", f"direct section {section} failed")

    status, payload = call(ctx, "invalid section generic", "GET", "/api/v1/interfaces/section/notreal")
    require(ctx, status == 422, "invalid generic section rejected", "invalid generic section not rejected")

    status, payload = call(ctx, "scan viewer/admin contract", "POST", "/api/v1/interfaces/scan")
    if ctx.identity.role == "viewer":
        require(ctx, status == 403, "viewer cannot run scan", "viewer scan was not forbidden")
    else:
        require(ctx, status == 200, "admin scan route is reachable", "admin scan route failed")
        _restore_candidate(before)

    for method, path, body in [
        ("POST", "/api/v1/interfaces/bridges", {"config": {"name": "br_nd_forbidden", "interfaces": "ens19"}}),
        ("PATCH", "/api/v1/interfaces/bridges/bridge-br0-19700101000000000-0001", {"config": {"dhcp4": "True"}}),
        ("DELETE", "/api/v1/interfaces/bridges/bridge-br0-19700101000000000-0001", None),
    ]:
        status, payload = call(ctx, f"mutation contract {method} {path}", method, path, body)
        if ctx.identity.role == "viewer":
            require(ctx, status == 403, f"viewer forbidden for {method} {path}", f"viewer not forbidden for {method} {path}")
        else:
            _restore_candidate(before)
            require(ctx, status in {200, 404, 422}, f"admin route {method} {path} is wired", f"admin route {method} {path} unexpected {status}")

    spec = _openapi()
    paths = [path for path in spec.get("paths", {}) if "/api/v1/interfaces" in path]
    require(ctx, not any(any(fragment in path for fragment in FORBIDDEN_PATH_FRAGMENTS) for path in paths), "OpenAPI has no forbidden interfaces paths", f"OpenAPI forbidden paths present: {paths}")
    for required_path in sorted(REQUIRED_OPENAPI_PATHS):
        require(ctx, required_path in paths, f"OpenAPI includes {required_path}", f"OpenAPI missing {required_path}")
    for collection in ["ethernets", "bridges", "bonds", "vlans", "wifis"]:
        collection_methods = set(spec["paths"][f"/api/v1/interfaces/{collection}"].keys())
        entry_methods = set(spec["paths"][f"/api/v1/interfaces/{collection}/{{uuid}}"].keys())
        require(ctx, EXPECTED_COLLECTION_METHODS.issubset(collection_methods), f"OpenAPI {collection} collection has GET/POST", f"OpenAPI {collection} collection methods wrong")
        require(ctx, {"patch", "delete"}.issubset(entry_methods), f"OpenAPI {collection} entry has PATCH/DELETE", f"OpenAPI {collection} entry methods wrong")

    after = INTERFACES.read_text(encoding="utf-8")
    require(ctx, after == before, "candidate/interfaces.json unchanged by non-destructive tests", "candidate/interfaces.json changed")
