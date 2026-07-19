"""Tests no destructivos de Monitor Logs."""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi import HTTPException
from common.runner import call, request, require

sys.path.insert(0, str(Path("fastApi/app").resolve()))
from modules.monitor_logs import service as monitor_service  # noqa: E402
from modules.monitor_logs.schemas import MonitorLogSearchRequest  # noqa: E402

BASE = "/api/v1/monitor-logs"
SERVICE_PATH = Path("fastApi/app/modules/monitor_logs/service.py")
RUNTIME_SCRIPT_PATH = "/var/lib/praesidium/scripts/checks/check_monitor_log_extract/extract_monitor_log_nftables_for_get_user.py"
RUNTIME_OUTPUT_DIR = "/var/lib/praesidium/state/monitor_log"
LEGACY_SCRIPT_PATH = "/var/www/backend/checks/check_monitor_log_extract/extract_monitor_log_nftables_for_get_user.py"
VALID_QUERY = {
    "Firewall": "",
    "Start_Date": "1970-01-01",
    "Start_Time": "00:00",
    "End_Date": "1970-01-01",
    "End_Time": "23:59",
    "Source_IP": "",
    "Destination_IP": "",
    "Source_Port": "",
    "Destination_Port": "",
    "Protocol": "",
    "Action": "",
    "Max_Records": "100",
}


def _detail(payload) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, dict):
            return str(detail.get("error_code") or detail)
        return str(detail)
    return str(payload)



def _valid_nftables_request() -> MonitorLogSearchRequest:
    return MonitorLogSearchRequest(**{**VALID_QUERY, "Firewall": "NFTABLES"})


def _expect_monitor_error(ctx, label: str, expected_code: str, script_text: str) -> None:
    tmp_script = Path(f"/tmp/praesidium_monitor_logs_{label}.py")
    original_script = monitor_service.SCRIPT_PATH
    tmp_script.write_text(script_text, encoding="utf-8")
    tmp_script.chmod(0o755)
    monitor_service.SCRIPT_PATH = tmp_script
    try:
        try:
            monitor_service.search_nftables(_valid_nftables_request(), ctx.identity.username)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            require(ctx, detail.get("error_code") == expected_code, f"{label} returns {expected_code}", f"{label} returned {exc.status_code}: {exc.detail}")
        else:
            require(ctx, False, f"{label} returns {expected_code}", f"{label} did not fail")
    finally:
        monitor_service.SCRIPT_PATH = original_script
        try:
            tmp_script.unlink()
        except FileNotFoundError:
            pass

def run(ctx) -> None:
    ctx.log("=== MONITOR LOGS NON-DESTRUCTIVE ===")
    service_text = SERVICE_PATH.read_text(encoding="utf-8")
    require(ctx, RUNTIME_SCRIPT_PATH in service_text, "FastAPI calls runtime monitor script", "runtime monitor script path missing")
    require(ctx, RUNTIME_OUTPUT_DIR in service_text or "repository.state_dir()" in service_text, "FastAPI reads runtime monitor state JSON", "runtime monitor output path missing")
    require(ctx, LEGACY_SCRIPT_PATH not in service_text and "/var/www/backend" not in service_text, "FastAPI does not use legacy /var/www script path", "legacy /var/www backend path found")
    require(ctx, "subprocess.run" in service_text, "FastAPI invokes backend script", "subprocess.run not found")
    require(ctx, 'data["user"] = user' in service_text, "FastAPI fixes user from token", "token user assignment missing")

    for label, method, path in [
        ("status", "GET", f"{BASE}/status"),
        ("list options", "GET", f"{BASE}/options"),
    ]:
        status, payload = call(ctx, label, method, path)
        require(ctx, status == 200, f"{label} readable", f"{label} failed {status}: {_detail(payload)}")

    for label, body, expected in [
        ("empty firewall returns empty", VALID_QUERY, 200),
        ("negative-invalid firewall", {**VALID_QUERY, "Firewall": "BAD"}, 422),
        ("negative-invalid protocol", {**VALID_QUERY, "Firewall": "NFTABLES", "Protocol": "BAD"}, 422),
        ("negative-invalid action", {**VALID_QUERY, "Firewall": "NFTABLES", "Action": "BAD"}, 422),
        ("negative-invalid max records", {**VALID_QUERY, "Firewall": "NFTABLES", "Max_Records": "999"}, 422),
        ("negative-invalid source ip", {**VALID_QUERY, "Firewall": "NFTABLES", "Source_IP": "999.999.999.999"}, 422),
        ("negative-invalid source port", {**VALID_QUERY, "Firewall": "NFTABLES", "Source_Port": "70000"}, 422),
        ("negative-invalid date range", {**VALID_QUERY, "Firewall": "NFTABLES", "Start_Date": "1970-01-01"}, 422),
    ]:
        status, payload = call(ctx, label, "POST", f"{BASE}/search", body)
        require(ctx, status == expected, f"{label} status {expected}", f"{label} returned {status}: {_detail(payload)}")

    _expect_monitor_error(ctx, "script_failed", "MONITOR_LOGS_SCRIPT_FAILED", "import sys\nsys.exit(7)\n")
    _expect_monitor_error(ctx, "output_missing", "MONITOR_LOGS_OUTPUT_NOT_FOUND", "# exits cleanly without writing output\n")

    status, openapi = request("GET", "/openapi.json", token=ctx.token)
    require(ctx, status == 200, "openapi readable", f"openapi failed {status}")
    paths = set(openapi.get("paths", {}).keys()) if isinstance(openapi, dict) else set()
    expected_paths = {f"{BASE}/status", f"{BASE}/options", f"{BASE}/search"}
    missing = sorted(path for path in expected_paths if path not in paths)
    require(ctx, not missing, "monitor-logs OpenAPI endpoints present", f"missing monitor-logs OpenAPI endpoints: {missing}")
    forbidden = [p for p in paths if p.startswith(BASE) and any(part in p for part in ["forms", "structure", "content", "table_content", "table_structure"])]
    require(ctx, not forbidden, "monitor-logs exposes no WebGUI helper routes", f"forbidden helper routes exposed: {forbidden}")
