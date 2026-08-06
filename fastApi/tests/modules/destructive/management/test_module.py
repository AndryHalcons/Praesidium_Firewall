"""Tests destructivos de Management."""
from __future__ import annotations

import json
from pathlib import Path

from common.runner import call, require as runner_require

BASE = "/api/v1/management"
CANDIDATE = Path("/var/lib/praesidium/candidate/management.json")


def _load() -> dict:
    return json.loads(CANDIDATE.read_text(encoding="utf-8"))


def _write(data: dict) -> None:
    CANDIDATE.write_text(json.dumps(data, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")


def check(ctx, condition: bool, message: str) -> None:
    runner_require(ctx, condition, message, message)


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code", detail))
        return str(detail)
    return str(payload)


def run(ctx) -> None:
    ctx.log("=== MANAGEMENT DESTRUCTIVE ===")
    original = _load()
    try:
        status, payload = call(ctx, "get listener before", "GET", f"{BASE}/listener")
        check(ctx, status == 200, "listener before failed")
        listener = payload["listener"]

        status, payload = call(ctx, "get tls before", "GET", f"{BASE}/tls")
        check(ctx, status == 200, "tls before failed")
        tls = payload["tls"]

        status, payload = call(ctx, "list allowed sources before", "GET", f"{BASE}/allowed-sources")
        check(ctx, status == 200, "allowed sources before failed")
        before_sources = payload["allowed_sources"]
        first_id = before_sources[0]["id"]

        if ctx.identity.role != "admin":
            viewer_mutations = [
                ("negative-viewer update listener", "PATCH", f"{BASE}/listener", listener, 403),
                ("negative-viewer update tls", "PATCH", f"{BASE}/tls", tls, 403),
                ("negative-viewer create allowed source", "POST", f"{BASE}/allowed-sources", {"source_cidr": "198.51.100.0/24", "description": "viewer"}, 403),
                ("negative-viewer update allowed source", "PATCH", f"{BASE}/allowed-sources/{first_id}", {"description": "viewer"}, 403),
                ("negative-viewer delete allowed source", "DELETE", f"{BASE}/allowed-sources/{first_id}", None, 403),
            ]
            for name, method, path, body, expected in viewer_mutations:
                status, payload = call(ctx, name, method, path, body)
                check(ctx, status == expected, f"{name} expected {expected}, got {status}: {_detail(payload)}")
            check(ctx, _load() == original, "viewer mutations changed candidate")
            return

        patched_listener = dict(listener)
        patched_listener["server_name"] = "praesidium.local"
        status, payload = call(ctx, "update listener same values", "PATCH", f"{BASE}/listener", patched_listener)
        check(ctx, status == 200 and payload.get("success") is True, "listener update failed")
        after_listener_data = _load()
        check(ctx, after_listener_data["table_management_listener"][0].get("UUID") == original["table_management_listener"][0].get("UUID"), "listener UUID not preserved")

        patched_tls = dict(tls)
        status, payload = call(ctx, "update tls same values", "PATCH", f"{BASE}/tls", patched_tls)
        check(ctx, status == 200 and payload.get("success") is True, "tls update failed")
        after_tls_data = _load()
        check(ctx, after_tls_data["table_management_tls"][0].get("UUID") == original["table_management_tls"][0].get("UUID"), "tls UUID not preserved")

        new_source = {"source_cidr": "198.51.100.0/24", "description": "fastapi destructive test"}
        status, payload = call(ctx, "create allowed source", "POST", f"{BASE}/allowed-sources", new_source)
        check(ctx, status == 200 and payload.get("success") is True, f"create source failed: {status} {payload}")
        created_id = payload.get("id")
        check(ctx, created_id, "created id missing")

        status, payload = call(ctx, "get created allowed source", "GET", f"{BASE}/allowed-sources/{created_id}")
        check(ctx, status == 200 and payload.get("allowed_source", {}).get("source_cidr") == new_source["source_cidr"], "created source not readable")

        status, payload = call(ctx, "negative-duplicate allowed source", "POST", f"{BASE}/allowed-sources", new_source)
        check(ctx, status == 409, f"duplicate source expected 409, got {status}: {_detail(payload)}")

        status, payload = call(ctx, "update allowed source", "PATCH", f"{BASE}/allowed-sources/{created_id}", {"description": "updated by fastapi"})
        check(ctx, status == 200 and payload.get("success") is True, "update source failed")

        status, payload = call(ctx, "delete allowed source", "DELETE", f"{BASE}/allowed-sources/{created_id}")
        check(ctx, status == 200 and payload.get("success") is True, "delete source failed")

        status, payload = call(ctx, "negative-delete missing allowed source", "DELETE", f"{BASE}/allowed-sources/{created_id}")
        check(ctx, status == 404, f"delete missing expected 404, got {status}: {_detail(payload)}")

    finally:
        _write(original)
        check(ctx, _load() == original, "candidate restore failed")
