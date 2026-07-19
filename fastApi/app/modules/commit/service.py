"""Lógica de negocio FastAPI para Commit."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from modules.commit import repository

SECRET_RE = re.compile(r"(pass|password|hash|secret|private[_-]?key|key\.private|token)", re.I)
ALLOWED_EXT = {"json", "yml", "yaml", "conf", "txt"}
BLOCKED_EXT = {"key", "pem", "crt", "cer", "csr", "req", "pfx", "p12", "pkcs12", "der", "jks", "srl", "lock", "jsonl"}
BLOCKED_FRAGMENTS = ["/commit_history/", "/security_audit/", "/certs/", "/conf.d/certs/", "/certificates/"]


def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY, extra: dict[str, Any] | None = None) -> None:
    detail = {"status": "error", "error_code": code}
    if extra:
        detail.update(extra)
    raise HTTPException(status_code=status_code, detail=detail)


def commit_user(user_name: str) -> dict[str, dict[str, str]]:
    return {"commit": {"date": datetime.now().strftime("%Y%m%d%H%M%S"), "user": user_name}}


def _is_secret_key(key: str) -> bool:
    return bool(SECRET_RE.search(key))


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            key_s = str(key)
            if key_s.lower() == "uuid":
                continue
            out[key] = "********" if _is_secret_key(key_s) else redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _label(obj: dict[str, Any]) -> str:
    for field in ["id", "name", "user_name", "interface", "display_name", "service_name", "source_cidr", "mac", "ip", "description", "server_name"]:
        value = obj.get(field)
        if str(value or "").strip():
            return f"{field}: {value}"
    return "objeto con UUID interno"


def _collect_uuid_objects(node: Any, path: str = "") -> dict[str, dict[str, Any]]:
    objects: dict[str, dict[str, Any]] = {}
    if isinstance(node, dict):
        uuid = node.get("UUID")
        if isinstance(uuid, str) and uuid:
            objects[uuid] = {"path": path or "/", "label": _label(node), "object": node}
        for key, value in node.items():
            if key == "UUID":
                continue
            if isinstance(value, (dict, list)):
                child = str(key) if path == "" else f"{path}/{key}"
                objects.update(_collect_uuid_objects(value, child))
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            if isinstance(value, (dict, list)):
                child = str(idx) if path == "" else f"{path}/{idx}"
                objects.update(_collect_uuid_objects(value, child))
    return objects


def _diff_fields(candidate: dict[str, Any], running: dict[str, Any]) -> list[dict[str, Any]]:
    candidate = dict(candidate)
    running = dict(running)
    candidate.pop("UUID", None)
    running.pop("UUID", None)
    changes = []
    for key in sorted(set(candidate) | set(running), key=str.lower):
        chas = key in candidate
        rhas = key in running
        cv = candidate.get(key)
        rv = running.get(key)
        if not chas or not rhas or cv != rv:
            secret = _is_secret_key(str(key))
            changes.append({
                "field": str(key),
                "before": None if not rhas else ("********" if secret else redact(rv)),
                "after": None if not chas else ("********" if secret else redact(cv)),
                "change": "field_added" if not rhas else ("field_deleted" if not chas else "field_modified"),
            })
    return changes


def _blocked(relative: str) -> bool:
    rel = "/" + relative.replace("\\", "/")
    return any(fragment in rel for fragment in BLOCKED_FRAGMENTS)


def preview() -> dict[str, Any]:
    summary = {"added": 0, "modified": 0, "deleted": 0, "unchanged": 0, "files": 0}
    changes: list[dict[str, Any]] = []
    candidate_root = repository.candidate_dir()
    running_root = repository.running_dir()
    files = sorted([p for p in candidate_root.rglob("*.json") if p.is_file() and not _blocked(str(p.relative_to(candidate_root)))], key=lambda p: str(p))
    for cpath in files:
        rel = str(cpath.relative_to(candidate_root))
        rpath = running_root / rel
        candidate_json = _load_json(cpath)
        running_json = _load_json(rpath)
        if not isinstance(candidate_json, (dict, list)) and not isinstance(running_json, (dict, list)):
            continue
        summary["files"] += 1
        cobjects = _collect_uuid_objects(candidate_json)
        robjects = _collect_uuid_objects(running_json)
        for uuid in sorted(set(cobjects) | set(robjects)):
            if uuid in cobjects and uuid not in robjects:
                summary["added"] += 1
                changes.append({"type": "added", "file": rel, "path": cobjects[uuid]["path"], "label": cobjects[uuid]["label"], "object": redact(cobjects[uuid]["object"])})
            elif uuid not in cobjects and uuid in robjects:
                summary["deleted"] += 1
                changes.append({"type": "deleted", "file": rel, "path": robjects[uuid]["path"], "label": robjects[uuid]["label"], "object": redact(robjects[uuid]["object"])})
            else:
                fields = _diff_fields(cobjects[uuid]["object"], robjects[uuid]["object"])
                if fields:
                    summary["modified"] += 1
                    changes.append({"type": "modified", "file": rel, "path": cobjects[uuid]["path"], "label": cobjects[uuid]["label"], "fields": fields, "candidate_object": redact(cobjects[uuid]["object"]), "running_object": redact(robjects[uuid]["object"]), "changed_fields": [f["field"] for f in fields]})
                else:
                    summary["unchanged"] += 1
    return {"success": True, "summary": summary, "changes": changes}


def _safe_file(path: Path, root: Path) -> bool:
    try:
        rel = str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return False
    ext = path.suffix.lower().lstrip(".")
    if ext in BLOCKED_EXT or ext not in ALLOWED_EXT:
        return False
    return not _blocked(rel)


def _redact_text(text: str) -> str:
    return re.sub(r"^(\s*(?:PrivateKey|private_key|client_private_key|key\.private)\s*=\s*).+$", r"\1********", text, flags=re.I | re.M)


def config_view(mode: str) -> dict[str, str]:
    roots = {"candidate": repository.candidate_dir(), "running": repository.running_dir()}
    if mode not in roots:
        fail("COMMIT_MODE_INVALID", status.HTTP_400_BAD_REQUEST)
    root = roots[mode]
    if not root.is_dir():
        fail("COMMIT_CONFIG_ROOT_NOT_FOUND", status.HTTP_404_NOT_FOUND)
    parts = [f"# Praesidium {mode} config\n"]
    for path in sorted([p for p in root.rglob("*") if p.is_file() and _safe_file(p, root)], key=lambda p: str(p)):
        rel = str(path.relative_to(root))
        content = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix.lower() == ".json":
            decoded = _load_json(path)
            if decoded is not None:
                content = json.dumps(redact(decoded), indent=2, ensure_ascii=False, sort_keys=True)
        else:
            content = _redact_text(content)
        parts.append(f"### {rel}\n{content}\n")
    return {"mode": mode, "content": "\n".join(parts)}


def apply_commit(user_name: str) -> dict[str, Any]:
    script = repository.commit_apply_path()
    if not script.exists():
        fail("COMMIT_BACKEND_NOT_FOUND", status.HTTP_500_INTERNAL_SERVER_ERROR)
    date = datetime.now().strftime("%Y%m%d%H%M%S%f")[:17]
    payload = {"commit": {"date": date, "user": user_name}}
    result = subprocess.run(["sudo", "-n", "/usr/bin/python3", str(script), json.dumps(payload)], text=True, capture_output=True, timeout=300, check=False)
    raw = (result.stdout or "").strip()
    if result.returncode != 0:
        return {"commit_result": {"status": "error", "error_code": "commit_backend_failed", "return_code": result.returncode, "output": (result.stderr or raw).strip()}, "message": "Commit failed.", "commit_details": []}
    try:
        commit_data = json.loads(raw)
    except Exception:
        return {"commit_result": {"status": "error", "error_code": "commit_backend_invalid_response"}, "message": "Commit backend returned an invalid response.", "commit_details": []}
    details = []
    history = repository.commits_dir() / "commit_history.json"
    if isinstance(commit_data, dict) and commit_data.get("date") and history.exists():
        hist = _load_json(history)
        if isinstance(hist, dict):
            details = hist.get("commits", {}).get(commit_data.get("date"), [])
    return {"commit_result": commit_data, "message": None, "commit_details": details}
