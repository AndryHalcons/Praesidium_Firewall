"""Tests destructivos de Commit."""
from __future__ import annotations

import json
from pathlib import Path

from common.runner import call, require

BASE = "/api/v1/commit"
CAND = Path("/var/lib/praesidium/candidate/fastapi_commit_test.json")
RUN = Path("/var/lib/praesidium/running/fastapi_commit_test.json")
UUID = "fastapi-commit-test-uuid"


def _backup(path: Path):
    return path.read_bytes() if path.exists() else None


def _restore(path: Path, data) -> None:
    if data is None:
        if path.exists():
            path.unlink()
    else:
        path.write_bytes(data)


def run(ctx) -> None:
    ctx.log("=== COMMIT DESTRUCTIVE ===")
    cand_bak = _backup(CAND)
    run_bak = _backup(RUN)
    try:
        CAND.write_text(json.dumps({"items": [{"UUID": UUID, "name": "commit-api-test", "value": "candidate", "private_key": "secret"}]}, indent=2), encoding="utf-8")
        RUN.write_text(json.dumps({"items": [{"UUID": UUID, "name": "commit-api-test", "value": "running", "private_key": "oldsecret"}]}, indent=2), encoding="utf-8")
        status, payload = call(ctx, "preview detects modified fixture", "GET", f"{BASE}/preview")
        require(ctx, status == 200, f"preview status ok", f"preview failed {status}: {payload}")
        changes = payload.get("changes", []) if isinstance(payload, dict) else []
        target = [c for c in changes if c.get("file") == "fastapi_commit_test.json"]
        require(ctx, bool(target), "preview includes fixture", f"fixture not in preview: {payload}")
        text = json.dumps(target, ensure_ascii=False)
        require(ctx, "candidate" in text and "running" in text, "preview shows before/after", f"preview missing values: {target}")
        require(ctx, "secret" not in text and "oldsecret" not in text and "********" in text, "preview redacts secrets", f"secret leaked: {target}")

        status, payload = call(ctx, "config candidate includes fixture redacted", "GET", f"{BASE}/config?mode=candidate")
        content = payload.get("content", "") if isinstance(payload, dict) else ""
        require(ctx, status == 200 and "fastapi_commit_test.json" in content, "config viewer includes fixture", f"config missing fixture: {status}")
        require(ctx, "secret" not in content and "********" in content, "config viewer redacts secrets", "config leaked secret")
    finally:
        _restore(CAND, cand_bak)
        _restore(RUN, run_bak)
        ctx.log("RESTORE commit fixture files restored")
