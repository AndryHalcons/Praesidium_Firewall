"""Lógica de negocio FastAPI para Monitor Logs."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from modules.monitor_logs import repository
from modules.monitor_logs.schemas import MonitorLogSearchRequest

OPTIONS = {
    "Protocol": ["", "TCP", "UDP", "ICMP", "ICMPV6"],
    "Action": ["", "ACCEPT", "DROP"],
    "Firewall": ["NFTABLES", "BPFILTER"],
    "Max_Records": ["100", "200", "500"],
}
LOG_COLUMNS = ["Date", "Time", "ID", "Chain", "Action", "SRC", "SPT", "DST", "DPT", "PROTO", "IN", "OUT"]
FILTER_COLUMNS = ["Start_Date", "Start_Time", "End_Date", "End_Time", "Source_IP", "Destination_IP", "Source_Port", "Destination_Port", "Protocol", "Action", "Firewall", "Max_Records"]
USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIME_RE = re.compile(r"^\d{2}:\d{2}$")
SCRIPT_PATH = Path("/var/lib/praesidium/scripts/checks/check_monitor_log_extract/extract_monitor_log_nftables_for_get_user.py")
PYTHON_BIN = "/usr/bin/python3"


# ES: Lanza un HTTPException estable con error_code para que WebGUI/tests no dependan de textos.
# EN: Raises a stable HTTPException with error_code so WebGUI/tests do not depend on text.
def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> None:
    """Lanza error estable status/error_code."""
    raise HTTPException(status_code=status_code, detail={"status": "error", "error_code": code})


# ES: Devuelve la metadata de filtros/columnas que puede consumir la UI.
# EN: Returns filter/column metadata that the UI can consume.
def options() -> dict[str, Any]:
    """Devuelve opciones declarativas del monitor."""
    return {"select": OPTIONS, "filters": FILTER_COLUMNS, "log_columns": LOG_COLUMNS}


# ES: Convierte cualquier valor recibido en string limpio para validar filtros.
# EN: Converts any received value into a trimmed string for filter validation.
def clean(value: Any) -> str:
    """Normaliza string."""
    return str(value or "").strip()


# ES: Valida el usuario autenticado que viene del token FastAPI, no del body.
# EN: Validates the authenticated user coming from the FastAPI token, not from the body.
def _validate_user(user_name: str) -> str:
    user = clean(user_name)
    if not USER_RE.fullmatch(user):
        fail("MONITOR_LOGS_USER_INVALID", status.HTTP_400_BAD_REQUEST)
    return user


# ES: Valida fechas/horas y comprueba que el rango inicio-fin sea coherente.
# EN: Validates dates/times and checks that the start-end range is coherent.
def _validate_date_time(start_date: str, start_time: str, end_date: str, end_time: str) -> tuple[str, str]:
    if not DATE_RE.fullmatch(start_date) or not DATE_RE.fullmatch(end_date):
        fail("MONITOR_LOGS_DATE_INVALID")
    if not TIME_RE.fullmatch(start_time) or not TIME_RE.fullmatch(end_time):
        fail("MONITOR_LOGS_TIME_INVALID")
    start = f"{start_date}T{start_time}"
    end = f"{end_date}T{end_time}"
    if start > end:
        fail("MONITOR_LOGS_RANGE_INVALID")
    return start, end


# ES: Valida IP opcional de filtro; vacío significa sin filtro.
# EN: Validates an optional IP filter; empty means no filter.
def _validate_ip(value: str, code: str) -> str:
    if not value:
        return ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        fail(code)
    return value


# ES: Valida puerto opcional de filtro dentro del rango TCP/UDP válido.
# EN: Validates an optional port filter within the valid TCP/UDP range.
def _validate_port(value: str, code: str) -> str:
    if not value:
        return ""
    if not value.isdigit():
        fail(code)
    port = int(value)
    if port < 1 or port > 65535:
        fail(code)
    return value


# ES: Valida todos los filtros aceptados por Monitor Logs antes de llamar al script.
# EN: Validates every accepted Monitor Logs filter before calling the script.
def _validate_payload(payload: MonitorLogSearchRequest) -> dict[str, str]:
    data = {field: clean(getattr(payload, field)) for field in FILTER_COLUMNS}
    firewall = data["Firewall"]
    if firewall not in {"", "NFTABLES", "BPFILTER"}:
        fail("MONITOR_LOGS_FIREWALL_INVALID")
    if data["Protocol"] not in OPTIONS["Protocol"]:
        fail("MONITOR_LOGS_PROTOCOL_INVALID")
    if data["Action"] not in OPTIONS["Action"]:
        fail("MONITOR_LOGS_ACTION_INVALID")
    if data["Max_Records"] not in OPTIONS["Max_Records"]:
        fail("MONITOR_LOGS_MAX_RECORDS_INVALID")
    _validate_date_time(data["Start_Date"], data["Start_Time"], data["End_Date"], data["End_Time"])
    _validate_ip(data["Source_IP"], "MONITOR_LOGS_SOURCE_IP_INVALID")
    _validate_ip(data["Destination_IP"], "MONITOR_LOGS_DESTINATION_IP_INVALID")
    _validate_port(data["Source_Port"], "MONITOR_LOGS_SOURCE_PORT_INVALID")
    _validate_port(data["Destination_Port"], "MONITOR_LOGS_DESTINATION_PORT_INVALID")
    return data


# ES: Calcula el JSON de salida que debe generar el script para el usuario autenticado.
# EN: Computes the output JSON path the script must generate for the authenticated user.
def _output_path(user_name: str) -> Path:
    return repository.state_dir() / f"{user_name}_log_view.json"


# ES: Ejecuta el script runtime real que extrae logs nftables y genera el JSON.
# EN: Runs the real runtime script that extracts nftables logs and generates JSON.
def _run_monitor_script(data: dict[str, str]) -> None:
    if not SCRIPT_PATH.is_file():
        fail("MONITOR_LOGS_SCRIPT_NOT_FOUND", status.HTTP_500_INTERNAL_SERVER_ERROR)
    command = [PYTHON_BIN, str(SCRIPT_PATH), json.dumps(data, ensure_ascii=False)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        fail("MONITOR_LOGS_SCRIPT_TIMEOUT", status.HTTP_504_GATEWAY_TIMEOUT)
    if completed.returncode != 0:
        fail("MONITOR_LOGS_SCRIPT_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR)


# ES: Flujo NFTABLES completo: fija user, ejecuta script, lee JSON y lo devuelve.
# EN: Full NFTABLES flow: fixes user, runs script, reads JSON, and returns it.
def search_nftables(payload: MonitorLogSearchRequest, user_name: str) -> dict[str, dict[str, str]]:
    """Ejecuta el script backend real y lee el JSON generado."""
    user = _validate_user(user_name)
    data = _validate_payload(payload)
    data["user"] = user
    output_path = _output_path(user)
    try:
        output_path.unlink(missing_ok=True)
    except OSError:
        fail("MONITOR_LOGS_OUTPUT_CLEANUP_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR)

    _run_monitor_script(data)

    if not output_path.is_file():
        fail("MONITOR_LOGS_OUTPUT_NOT_FOUND", status.HTTP_500_INTERNAL_SERVER_ERROR)
    try:
        content = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        fail("MONITOR_LOGS_OUTPUT_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
    if not isinstance(content, dict):
        fail("MONITOR_LOGS_OUTPUT_INVALID", status.HTTP_500_INTERNAL_SERVER_ERROR)
    return content


# ES: Despacha la búsqueda según Firewall conservando BPFILTER como no implementado.
# EN: Dispatches the search by Firewall while keeping BPFILTER as not implemented.
def search_logs(payload: MonitorLogSearchRequest, user_name: str) -> Any:
    """Despacha búsqueda según firewall."""
    firewall = clean(payload.Firewall)
    if firewall == "NFTABLES":
        return search_nftables(payload, user_name)
    if firewall == "BPFILTER":
        return {"info": "BPFILTER aún no implementado"}
    if firewall == "":
        return []
    fail("MONITOR_LOGS_FIREWALL_INVALID")
