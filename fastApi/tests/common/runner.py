"""
Utilidades compartidas para orquestadores y tests FastAPI.
Shared utilities for FastAPI orchestrators and tests.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.test_identities import TestIdentity

BASE_URL = "http://127.0.0.1:8000"
CANDIDATE = Path("/var/lib/praesidium/candidate/users.json")
RUNNING = Path("/var/lib/praesidium/running/users.json")

class TestFailure(RuntimeError):
    pass

@dataclass
class RequestSummary:
    """Resumen de una request. / One request summary row."""
    module_name: str
    role: str
    identity: str
    name: str
    method: str
    path: str
    status: int
    detail: str


@dataclass
class TestContext:
    """Contexto inyectado por el orquestador. / Context injected by the orchestrator."""
    identity: TestIdentity
    token: str
    current_password: str
    module_name: str
    mode: str
    report_path: Path
    lines: list[str] = field(default_factory=list)
    request_summaries: list[RequestSummary] = field(default_factory=list)

    def log(self, text: str = "") -> None:
        # ES: Registra una línea en el informe y en consola.
        # EN: Record one line in the report and console.
        self.lines.append(text)
        print(text)

    def write_report(self) -> None:
        # ES: Escribe el informe final en la carpeta central de reports.
        # EN: Write the final report in the central reports folder.
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")

def read_candidate() -> dict[str, Any]:
    # ES: Lee candidate para verificar efectos reales.
    # EN: Read candidate to verify real effects.
    return json.loads(CANDIDATE.read_text(encoding="utf-8"))

def users(data: dict[str, Any]) -> list[dict[str, Any]]:
    # ES: Extrae table_users de forma defensiva.
    # EN: Extract table_users defensively.
    value = data.get("table_users", [])
    return value if isinstance(value, list) else []

def policy(data: dict[str, Any]) -> dict[str, Any]:
    # ES: Extrae la política singleton.
    # EN: Extract the singleton policy.
    table = data.get("table_password_policy", [])
    return table[0] if isinstance(table, list) and table and isinstance(table[0], dict) else {}

def find_user_by_name(name: str) -> dict[str, Any] | None:
    # ES: Busca usuario por user_name en candidate.
    # EN: Find a user by user_name in candidate.
    for user in users(read_candidate()):
        if user.get("user_name") == name:
            return user
    return None

def find_user_by_uuid(uuid: str) -> dict[str, Any] | None:
    # ES: Busca usuario por UUID interno en candidate.
    # EN: Find a user by internal UUID in candidate.
    for user in users(read_candidate()):
        if user.get("UUID") == uuid:
            return user
    return None

def request(method: str, path: str, body: dict[str, Any] | None = None, token: str | None = None) -> tuple[int, Any]:
    # ES: Ejecuta una solicitud HTTP contra FastAPI.
    # EN: Execute an HTTP request against FastAPI.
    headers: dict[str, str] = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            payload = json.loads(raw)
        except Exception:
            payload = raw
        return exc.code, payload

def extract_detail(payload: Any) -> str:
    # ES: Extrae un detalle corto para el resumen comparativo.
    # EN: Extract a short detail for the comparative summary.
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
        if isinstance(detail, list) and detail:
            first = detail[0]
            if isinstance(first, dict):
                return str(first.get("type") or first.get("msg") or "validation_error")
            return str(first)
        if "status" in payload:
            return str(payload.get("status"))
        if "deleted_uuid" in payload:
            return "deleted"
        if "UUID" in payload:
            return "ok"
        if "users" in payload:
            return "ok"
        if "policy" in payload:
            return "ok"
        if "attempts" in payload:
            return "ok"
    if payload in ({}, None):
        return ""
    return str(payload)[:80]


def call_with_token(ctx: TestContext, name: str, method: str, path: str, body: dict[str, Any] | None = None, token: str | None = None) -> tuple[int, Any]:
    # ES: Ejecuta y registra una solicitud usando el token indicado.
    # EN: Execute and log a request using the selected token.
    status, payload = request(method, path, body, token)
    report_name = f"negative-{name}" if status >= 400 and not name.startswith("negative-") else name
    ctx.request_summaries.append(RequestSummary(ctx.module_name, ctx.identity.role, ctx.identity.username, report_name, method, path, status, extract_detail(payload)))
    ctx.log(f"REQUEST {report_name}: {method} {path}")
    if body is not None:
        safe_body = dict(body)
        for key in ["user_pass", "password", "current_password", "new_password", "confirm_password"]:
            if key in safe_body:
                safe_body[key] = "<redacted>"
        ctx.log(f"BODY {json.dumps(safe_body, ensure_ascii=False, sort_keys=True)}")
    preview = dict(payload) if isinstance(payload, dict) else payload
    if isinstance(preview, dict) and "access_token" in preview:
        preview["access_token"] = "<token>"
    response_text = json.dumps(preview, ensure_ascii=False, sort_keys=True)
    if len(response_text) > 2000:
        response_text = response_text[:2000] + "... <truncated>"
    ctx.log(f"RESPONSE {status}: {response_text}")
    return status, payload

def call(ctx: TestContext, name: str, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
    # ES: Ejecuta y registra una solicitud usando el token inyectado.
    # EN: Execute and log a request using the injected token.
    return call_with_token(ctx, name, method, path, body, ctx.token)

def require(ctx: TestContext, condition: bool, ok: str, fail: str) -> None:
    # ES: Registra OK o aborta el test.
    # EN: Log OK or abort the test.
    if not condition:
        ctx.log(f"FAIL {fail}")
        raise TestFailure(fail)
    ctx.log(f"OK {ok}")

def login(identity: TestIdentity, allow_password_change: bool = False) -> tuple[str, str]:
    # ES: Login del usuario inyectado; si exige cambio, usa contraseña temporal única.
    # EN: Login the injected user; if forced, use a unique temporary password.
    status, payload = request("POST", "/api/v1/auth/login", {"username": identity.username, "password": identity.password})
    if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
        raise TestFailure(f"login failed for {identity.username}: {status} {payload}")
    token = payload["access_token"]
    current_password = identity.password
    if payload.get("password_change_required") is True:
        if not allow_password_change:
            raise TestFailure(f"password change required for {identity.username}; non-destructive login must not mutate state")
        temporary_password = f"Malicotea{int(time.time())}A*"
        status, changed = request("POST", "/api/v1/auth/change-password", {"current_password": identity.password, "new_password": temporary_password, "confirm_password": temporary_password}, token)
        if status != 200:
            raise TestFailure(f"mandatory password change failed for {identity.username}: {status} {changed}")
        status, payload = request("POST", "/api/v1/auth/login", {"username": identity.username, "password": temporary_password})
        if status != 200 or not payload.get("access_token"):
            raise TestFailure(f"relogin failed for {identity.username}: {status} {payload}")
        token = payload["access_token"]
        current_password = temporary_password
    return token, current_password

def load_module(path: Path):
    # ES: Carga dinámicamente un módulo de test por ruta.
    # EN: Dynamically load a test module by path.
    spec = importlib.util.spec_from_file_location(f"praesidium_test_{path.parent.name}", path)
    if spec is None or spec.loader is None:
        raise TestFailure(f"cannot load module {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def summary_expected_ok(row: RequestSummary) -> bool:
    # ES: negative-viewer/admin compara admin permitido contra viewer denegado.
    # EN: negative-viewer/admin compares allowed admin against denied viewer.
    if row.name.startswith("negative-viewer/admin"):
        return row.status >= 400 if row.role == "viewer" else row.status < 400
    # ES: negative-* espera error HTTP; el resto espera respuesta no-error.
    # EN: negative-* expects an HTTP error; the rest expects a non-error response.
    if row.name.startswith("negative-"):
        return row.status >= 400
    return row.status < 400


def write_mode_summary(reports_dir: Path, mode: str, rows: list[RequestSummary]) -> None:
    # ES: Genera una tabla comparativa con resultado visual y conteo total.
    # EN: Generate a comparative table with visual result and total counts.
    reports_dir.mkdir(parents=True, exist_ok=True)
    summary_path = reports_dir / "summary.txt"
    roles = sorted({row.role for row in rows})
    ordered_keys: list[tuple[str, str, str]] = []
    by_key: dict[tuple[str, str, str], dict[str, RequestSummary]] = {}
    for row in rows:
        key = (row.module_name, row.name, row.method)
        if key not in by_key:
            by_key[key] = {}
            ordered_keys.append(key)
        by_key[key][row.role] = row
    headers = ["MODULE", "REQUEST", "METHOD", *[role.upper() for role in roles]]
    lines = [f"Praesidium FastAPI {mode} comparative summary", f"generated={datetime.now(timezone.utc).isoformat()}", ""]
    ok_count = 0
    fail_count = 0
    table_rows: list[list[str]] = []
    for module_name, name, method in ordered_keys:
        row_values = [module_name, name, method]
        for role in roles:
            item = by_key[(module_name, name, method)].get(role)
            if item is None:
                row_values.append("⏭ no ejecutado")
            else:
                expected_ok = summary_expected_ok(item)
                icon = "✅" if expected_ok else "❌"
                if expected_ok:
                    ok_count += 1
                else:
                    fail_count += 1
                suffix = f" {item.detail}" if item.detail else ""
                row_values.append(f"{icon} {item.status}{suffix}")
        table_rows.append(row_values)
    widths = [len(header) for header in headers]
    for row in table_rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(value))
    fmt = "  ".join(f"{{:<{width}}}" for width in widths)
    lines.append(fmt.format(*headers))
    lines.append(fmt.format(*["-" * width for width in widths]))
    for row in table_rows:
        lines.append(fmt.format(*row))
    lines.extend(["", "TOTAL", f"✅ {ok_count}", f"❌ {fail_count}"])
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"summary={summary_path}")

def run_mode(tests_root: Path, mode: str, identities: tuple[TestIdentity, ...]) -> int:
    # ES: Recorre módulos del modo indicado e inyecta cada identidad.
    # EN: Walk modules for the selected mode and inject each identity.
    modules_dir = tests_root / "modules" / mode
    reports_dir = tests_root / "reports" / mode
    backup_candidate = Path(f"/tmp/praesidium_{mode}_candidate_before_orchestrator.json")
    backup_running = Path(f"/tmp/praesidium_{mode}_running_before_orchestrator.json")
    if not modules_dir.is_dir():
        print(f"No modules directory: {modules_dir}")
        return 1
    exit_code = 0
    module_files = sorted(mod / "test_module.py" for mod in modules_dir.iterdir() if mod.is_dir() and (mod / "test_module.py").is_file())
    module_filter = os.environ.get("PRAESIDIUM_TEST_MODULE", "").strip()
    if module_filter:
        module_files = [path for path in module_files if path.parent.name == module_filter]
    if not module_files:
        print(f"No test_module.py files found in {modules_dir}")
        return 1
    all_request_summaries: list[RequestSummary] = []
    for module_file in module_files:
        module_name = module_file.parent.name
        for identity in identities:
            report_path = reports_dir / f"{module_name}_{identity.role}.txt"
            ctx = TestContext(identity=identity, token="", current_password=identity.password, module_name=module_name, mode=mode, report_path=report_path)
            ctx.log(f"Praesidium FastAPI {mode} module test")
            ctx.log(f"module={module_name}")
            ctx.log(f"identity={identity.username}")
            ctx.log(f"role={identity.role}")
            ctx.log(f"start={datetime.now(timezone.utc).isoformat()}")
            shutil.copy2(CANDIDATE, backup_candidate)
            shutil.copy2(RUNNING, backup_running)
            try:
                ctx.token, ctx.current_password = login(identity, allow_password_change=(mode == "destructive"))
                mod = load_module(module_file)
                if not hasattr(mod, "run"):
                    raise TestFailure(f"{module_file} has no run(ctx) function")
                mod.run(ctx)
                ctx.log("FINAL RESULT: OK")
            except Exception as exc:
                exit_code = 1
                ctx.log(f"FINAL RESULT: FAIL {exc}")
                ctx.log(traceback.format_exc())
            finally:
                if mode == "destructive":
                    shutil.copy2(backup_candidate, CANDIDATE)
                    shutil.copy2(backup_running, RUNNING)
                    ctx.log("RESTORE candidate/running applied")
                ctx.write_report()
                all_request_summaries.extend(ctx.request_summaries)
                print(f"report={report_path}")
    write_mode_summary(reports_dir, mode, all_request_summaries)
    return exit_code
