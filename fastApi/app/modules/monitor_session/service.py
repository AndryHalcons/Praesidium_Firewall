"""Lógica de negocio FastAPI para Monitor Session."""

from __future__ import annotations

import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from fastapi import HTTPException, status

from modules.monitor_session import repository
from modules.monitor_session.schemas import SessionCommandRequest

USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:,@=+-]+$")
QUERY_ACTIONS = {"-L", "-E", "-C", "-S"}
MUTATION_ACTIONS = {"-D", "-F"}
ALLOWED_ACTIONS = QUERY_ACTIONS | MUTATION_ACTIONS
UNSAFE_FRAGMENTS = (";", "&&", "||", "|", ">", "<", "`", "$(", "\n", "\r")
UNSAFE_WORDS = {
    "bash", "sh", "sudo", "su", "python", "python3", "perl", "ruby", "php",
    "rm", "mv", "cp", "chmod", "chown", "curl", "wget", "nc", "ncat", "socat",
    "reboot", "shutdown", "halt", "poweroff", "systemctl", "service", "iptables", "nft",
}
DISALLOWED_FLAGS = {"-o", "--output"}
COLUMNS = [
    "PROTO",
    "STATE",
    "SOURCE",
    "SRC PORT",
    "DESTINATION",
    "DST PORT",
    "REPLY SOURCE",
    "REPLY SRC PORT",
    "REPLY DESTINATION",
    "REPLY DST PORT",
    "TIMEOUT",
    "ASSURED",
    "ID",
]


# ES: Lanza error estable status/error_code consumible por tests y WebGUI.
# EN: Raises a stable status/error_code error consumable by tests and WebGUI.
def fail(code: str, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY, extra: dict[str, Any] | None = None) -> None:
    detail: dict[str, Any] = {"status": "error", "error_code": code}
    if extra:
        detail.update(extra)
    raise HTTPException(status_code=status_code, detail=detail)


# ES: Valida el usuario autenticado usado para nombrar snapshots.
# EN: Validates the authenticated user used to name snapshots.
def validate_user(user_name: str) -> str:
    user = str(user_name or "").strip()
    if not USER_RE.fullmatch(user):
        fail("MONITOR_SESSION_USER_INVALID", status.HTTP_400_BAD_REQUEST)
    return user


# ES: Lee texto XML con valor por defecto para celdas ausentes.
# EN: Reads XML text with a default value for missing cells.
def _find_text(flow: ET.Element, path: str, default: str = "-") -> str:
    node = flow.find(path)
    if node is None:
        return default
    value = (node.text or "").strip()
    return value or default


# ES: Lee un atributo XML con valor por defecto para celdas ausentes.
# EN: Reads an XML attribute with a default value for missing cells.
def _find_attr(flow: ET.Element, path: str, attr: str, default: str = "-") -> str:
    node = flow.find(path)
    if node is None:
        return default
    value = (node.attrib.get(attr) or "").strip()
    return value or default


# ES: Convierte presencia de nodo XML en yes/no.
# EN: Converts XML node presence into yes/no.
def _has_node(flow: ET.Element, path: str) -> str:
    return "yes" if flow.find(path) is not None else "no"


# ES: Indica si existe snapshot XML para el usuario autenticado.
# EN: Indicates whether an XML snapshot exists for the authenticated user.
def snapshot_exists(user_name: str) -> bool:
    user = validate_user(user_name)
    return repository.snapshot_path(user).exists()


# ES: Lee el snapshot XML del usuario y lo convierte en filas JSON normalizadas.
# EN: Reads the user's XML snapshot and converts it into normalized JSON rows.
def read_rows(user_name: str) -> tuple[list[dict[str, str]], bool]:
    user = validate_user(user_name)
    path = repository.snapshot_path(user)
    if not path.exists():
        return [], False
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        fail("MONITOR_SESSION_XML_READ_ERROR", status.HTTP_500_INTERNAL_SERVER_ERROR)
    rows: list[dict[str, str]] = []
    for flow in list(root.findall("flow")):
        rows.append({
            "proto": _find_attr(flow, './meta[@direction="original"]/layer4', "protoname"),
            "state": _find_text(flow, './meta[@direction="independent"]/state'),
            "source": _find_text(flow, './meta[@direction="original"]/layer3/src'),
            "source_port": _find_text(flow, './meta[@direction="original"]/layer4/sport'),
            "destination": _find_text(flow, './meta[@direction="original"]/layer3/dst'),
            "destination_port": _find_text(flow, './meta[@direction="original"]/layer4/dport'),
            "reply_source": _find_text(flow, './meta[@direction="reply"]/layer3/src'),
            "reply_source_port": _find_text(flow, './meta[@direction="reply"]/layer4/sport'),
            "reply_destination": _find_text(flow, './meta[@direction="reply"]/layer3/dst'),
            "reply_destination_port": _find_text(flow, './meta[@direction="reply"]/layer4/dport'),
            "timeout": _find_text(flow, './meta[@direction="independent"]/timeout'),
            "assured": _has_node(flow, './meta[@direction="independent"]/assured'),
            "id": _find_text(flow, './meta[@direction="independent"]/id'),
        })
    return rows, True


# ES: Normaliza arguments aceptando null, string vacío, string shlex o lista de strings.
# EN: Normalizes arguments accepting null, empty string, shlex string, or string list.
def normalize_arguments(arguments: str | list[str] | None) -> list[str]:
    if arguments is None:
        return []
    if isinstance(arguments, str):
        text = arguments.strip()
        if text == "" or text.lower() == "null":
            return []
        try:
            return shlex.split(text)
        except ValueError:
            fail("MONITOR_SESSION_ARGUMENTS_INVALID")
    if isinstance(arguments, list):
        normalized: list[str] = []
        for value in arguments:
            text = str(value or "").strip()
            if text == "" or text.lower() == "null":
                continue
            normalized.append(text)
        return normalized
    fail("MONITOR_SESSION_ARGUMENTS_INVALID")


# ES: Rechaza tokens que intenten salir del dominio de argumentos conntrack.
# EN: Rejects tokens that try to escape the conntrack-arguments domain.
def validate_argument_token(token: str) -> str:
    if not token or len(token) > 128:
        fail("MONITOR_SESSION_ARGUMENT_TOKEN_INVALID")
    lowered = token.lower()
    if token in DISALLOWED_FLAGS:
        fail("MONITOR_SESSION_OUTPUT_FLAG_FORBIDDEN")
    if any(fragment in token for fragment in UNSAFE_FRAGMENTS):
        fail("MONITOR_SESSION_UNSAFE_ARGUMENT")
    if "/" in token or "\\" in token:
        fail("MONITOR_SESSION_PATH_ARGUMENT_FORBIDDEN")
    if lowered in UNSAFE_WORDS:
        fail("MONITOR_SESSION_COMMAND_WORD_FORBIDDEN")
    if not SAFE_TOKEN_RE.fullmatch(token):
        fail("MONITOR_SESSION_ARGUMENT_TOKEN_INVALID")
    return token


# ES: Valida acción, argumentos y permisos de rol antes de llamar al wrapper backend.
# EN: Validates action, arguments, and role permissions before calling the backend wrapper.
def validate_command(payload: SessionCommandRequest, user: dict[str, str]) -> tuple[str, list[str]]:
    action = str(payload.action or "").strip()
    if action not in ALLOWED_ACTIONS:
        fail("MONITOR_SESSION_ACTION_NOT_ALLOWED")
    if action in MUTATION_ACTIONS and user.get("user_role") != "admin":
        fail("ADMIN_REQUIRED", status.HTTP_403_FORBIDDEN)
    args = [validate_argument_token(token) for token in normalize_arguments(payload.arguments)]
    return action, args


# ES: Ejecuta el script backend con sudo -n como única elevación permitida.
# EN: Runs the backend script with sudo -n as the only allowed elevation.
def run_backend_script(user_name: str, action: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    user = validate_user(user_name)
    script = repository.extractor_path()
    if not script.exists():
        fail("MONITOR_SESSION_EXTRACTOR_NOT_FOUND", status.HTTP_500_INTERNAL_SERVER_ERROR)
    command = ["sudo", "-n", "/usr/bin/python3", str(script), "--user", user, action, *arguments]
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=25, check=False)
    except subprocess.TimeoutExpired as exc:
        output = "\n".join(part for part in [str(exc.stdout or "").strip(), str(exc.stderr or "").strip()] if part)
        fail("MONITOR_SESSION_COMMAND_TIMEOUT", status.HTTP_500_INTERNAL_SERVER_ERROR, {"output": output})


# ES: Une stdout/stderr real para devolver diagnósticos de conntrack sin inventarlos.
# EN: Joins real stdout/stderr to return conntrack diagnostics without inventing them.
def command_output(result: subprocess.CompletedProcess[str]) -> str:
    return "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)


# ES: Ejecuta una acción conntrack validada y adapta respuesta según consulta o destructiva.
# EN: Runs a validated conntrack action and adapts the response for query or mutation.
def run_command(payload: SessionCommandRequest, user: dict[str, str]) -> dict[str, Any]:
    user_name = validate_user(user["user_name"])
    action, arguments = validate_command(payload, user)
    result = run_backend_script(user_name, action, arguments)
    output = command_output(result)
    if result.returncode != 0:
        fail("MONITOR_SESSION_COMMAND_FAILED", status.HTTP_500_INTERNAL_SERVER_ERROR, {"output": output, "return_code": result.returncode})
    rows: list[dict[str, str]] = []
    has_snapshot = False
    if action in QUERY_ACTIONS:
        rows, has_snapshot = read_rows(user_name)
    return {
        "status": "ok",
        "action": action,
        "arguments": arguments,
        "output": output,
        "return_code": result.returncode,
        "rows": rows,
        "has_snapshot": has_snapshot,
    }


# ES: Compatibilidad del botón clásico: refresh equivale a consulta -L sin argumentos.
# EN: Classic button compatibility: refresh equals a -L query without arguments.
def refresh_snapshot(user: dict[str, str]) -> dict[str, Any]:
    result = run_command(SessionCommandRequest(action="-L", arguments=None), user)
    return {"status": result["status"], "message": "sessions reloaded", "output": result["output"], "rows": result["rows"]}
