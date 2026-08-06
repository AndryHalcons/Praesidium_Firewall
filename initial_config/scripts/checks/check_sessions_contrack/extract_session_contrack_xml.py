#!/usr/bin/env python3
"""
###############################################################################
  Extractor/wrapper controlado de conntrack por usuario
  Controlled per-user conntrack extractor/wrapper

  Responsabilidades / Responsibilities:
    - Ejecutar conntrack con una acción permitida.
      Run conntrack with an allowed action.
    - Mantener XML para operaciones de consulta cuando conntrack lo soporte.
      Keep XML for query operations when conntrack supports it.
    - Escribir snapshot XML atómico por usuario para salidas XML válidas.
      Write an atomic per-user XML snapshot for valid XML outputs.
    - Devolver stdout/stderr reales de conntrack para combinaciones no soportadas.
      Return real conntrack stdout/stderr for unsupported combinations.

  Límites / Boundaries:
    - El binario conntrack está hardcodeado.
      The conntrack binary is hardcoded.
    - Sólo acepta acciones permitidas: -L, -E, -C, -S, -D, -F.
      It only accepts allowed actions: -L, -E, -C, -S, -D, -F.
    - No usa shell=True ni concatena comandos de shell.
      It does not use shell=True or concatenate shell commands.
###############################################################################
"""

import argparse
import os
import re
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

OUTPUT_DIR = "/var/lib/praesidium/state/sessions_contrack"
CONNTRACK = "/usr/sbin/conntrack"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
QUERY_ACTIONS = {"-L", "-E", "-C", "-S"}
MUTATION_ACTIONS = {"-D", "-F"}
ALLOWED_ACTIONS = QUERY_ACTIONS | MUTATION_ACTIONS
DEFAULT_QUERY_TIMEOUT = 15
EVENT_QUERY_TIMEOUT = 5


# ES: Lee --user con argparse y deja acción/filtros para parseo manual porque empiezan por guion.
# EN: Reads --user with argparse and leaves action/filters for manual parsing because they start with dashes.
def parse_args():
    parser = argparse.ArgumentParser(description="Run controlled conntrack action as per-user backend")
    parser.add_argument("--user", required=True, help="Praesidium username")
    known, remaining = parser.parse_known_args()
    if not remaining:
        parser.error("missing conntrack action: expected one of -L -E -C -S -D -F")
    action = remaining[0]
    if action not in ALLOWED_ACTIONS:
        parser.error(f"unsupported conntrack action: {action}")
    extra = split_extra_args(remaining[1:])
    return known.user, action, extra


# ES: Normaliza el tercer atributo opcional; acepta vacío, null o una cadena con varios argumentos.
# EN: Normalizes the optional third attribute; accepts empty, null, or one string with several arguments.
def split_extra_args(values):
    args = []
    for value in values:
        text = str(value or "").strip()
        if text == "" or text.lower() == "null":
            continue
        args.extend(shlex.split(text))
    return args


# ES: Construye la ruta de salida a partir de un usuario previamente validado.
# EN: Builds the output path from a previously validated username.
def safe_output_path(username: str) -> str:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("invalid username")
    return os.path.join(OUTPUT_DIR, f"{username}_session_conntrack.xml")


# ES: Añade -o xml a consultas que no lo traigan ya; destructivas no fuerzan XML.
# EN: Adds -o xml to queries that do not already include it; mutations do not force XML.
def build_command(action: str, extra_args: list[str]) -> list[str]:
    command = [CONNTRACK, action]
    command.extend(extra_args)
    if action in QUERY_ACTIONS and "-o" not in extra_args and "--output" not in extra_args:
        command.extend(["-o", "xml"])
    return command


# ES: Escribe XML válido de forma atómica para el snapshot del usuario.
# EN: Writes valid XML atomically for the user's snapshot.
def write_xml_snapshot(output_path: str, xml_data: str) -> None:
    os.makedirs(OUTPUT_DIR, mode=0o755, exist_ok=True)
    ET.fromstring(xml_data)
    fd, tmp_path = tempfile.mkstemp(prefix=".session_conntrack.", suffix=".xml", dir=OUTPUT_DIR, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(xml_data)
            if not xml_data.endswith("\n"):
                handle.write("\n")
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, output_path)
        os.chmod(output_path, 0o644)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ES: Ejecuta conntrack, guarda XML sólo cuando la acción es consulta y stdout es XML válido.
# EN: Runs conntrack, storing XML only when the action is a query and stdout is valid XML.
def main() -> int:
    username, action, extra_args = parse_args()
    try:
        output_path = safe_output_path(username)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    command = build_command(action, extra_args)
    timeout = EVENT_QUERY_TIMEOUT if action == "-E" else DEFAULT_QUERY_TIMEOUT
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        if action == "-E" and stdout:
            result = subprocess.CompletedProcess(command, 0, stdout, stderr or "conntrack event capture timed out after sample window")
        else:
            sys.stderr.write(stderr or f"conntrack timed out after {timeout}s\n")
            return 124

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if action in QUERY_ACTIONS and stdout:
        try:
            write_xml_snapshot(output_path, stdout)
            print(output_path)
        except ET.ParseError:
            if stdout:
                print(stdout)
            if stderr:
                print(stderr, file=sys.stderr)
            return result.returncode or 1
    elif action in QUERY_ACTIONS and result.returncode == 0:
        empty_xml = '<?xml version="1.0" encoding="utf-8"?>\n<conntrack>\n</conntrack>\n'
        write_xml_snapshot(output_path, empty_xml)
        print(output_path)
    elif stdout:
        print(stdout)

    if stderr:
        print(stderr, file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
