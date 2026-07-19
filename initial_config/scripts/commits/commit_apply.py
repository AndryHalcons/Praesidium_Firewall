#!/usr/bin/env python3
"""
ES:
    Entrada privilegiada del pipeline de commit Praesidium.

    Recibe un JSON ya construido por la WebGUI/PHP, toma date/user y ejecuta
    start_commit_process(). Este archivo no genera mensajes visibles para el
    usuario: devuelve estados/códigos técnicos para que PHP/idioma decidan el
    texto final.

    Para evitar carreras, sólo permite un commit en curso usando flock() no
    bloqueante sobre /var/lib/praesidium/commits/.commit_apply.lock.

EN:
    Privileged entry point for the Praesidium commit pipeline.

    It receives JSON already built by the WebGUI/PHP layer, reads date/user and
    runs start_commit_process(). This file does not generate user-visible text:
    it returns technical states/codes so PHP/language files choose the final
    message.

    To avoid races, it allows only one active commit through a non-blocking
    flock() on /var/lib/praesidium/commits/.commit_apply.lock.
"""

from __future__ import annotations

import fcntl
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
COMMIT_TASK_DIR = SCRIPT_DIR / 'commit_task'
sys.path.insert(0, str(COMMIT_TASK_DIR))
from main_task import start_commit_process  # noqa: E402

LOCK_PATH = Path('/var/lib/praesidium/commits/.commit_apply.lock')


def _json_response(payload: dict, exit_code: int = 0) -> None:
    """
    ES: Emite una única respuesta JSON y termina con el código indicado.
    EN: Emit one JSON response and exit with the requested code.
    """
    print(json.dumps(payload))
    raise SystemExit(exit_code)


def _open_commit_lock():
    """
    ES:
        Abre y bloquea el lock global de commit sin esperar.

        Si otro commit está activo, no hacemos cola: devolvemos busy para que
        la WebGUI informe al usuario y éste reintente cuando termine el commit
        actual.

    EN:
        Open and acquire the global commit lock without waiting.

        If another commit is active, do not queue: return busy so the WebGUI can
        inform the user and they can retry after the current commit finishes.
    """
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = LOCK_PATH.open('w', encoding='utf-8')
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        _json_response({
            'status': 'busy',
            'error_code': 'commit_already_running'
        }, 2)

    handle.write('locked\n')
    handle.flush()
    return handle


def start_commit(user: str, date: str) -> tuple[str | None, str | None]:
    """
    ES: Ejecuta el pipeline real de commit.
    EN: Execute the real commit pipeline.
    """
    try:
        start_commit_process(user, date)
        return date, user
    except Exception:
        return None, None


def main() -> None:
    """
    ES: Valida entrada mínima, adquiere lock y ejecuta el commit.
    EN: Validate minimal input, acquire lock and execute the commit.
    """
    if len(sys.argv) < 2:
        _json_response({'status': 'error', 'error_code': 'missing_json'}, 1)

    try:
        commit_data = json.loads(sys.argv[1])
        date = commit_data['commit']['date']
        user = commit_data['commit']['user']
    except json.JSONDecodeError:
        _json_response({'status': 'error', 'error_code': 'invalid_json'}, 1)
    except KeyError:
        _json_response({'status': 'error', 'error_code': 'missing_commit_fields'}, 1)

    lock_handle = _open_commit_lock()
    try:
        date, user = start_commit(str(user), str(date))
        _json_response({
            'status': 'ok',
            'date': date,
            'user': user
        })
    finally:
        # ES: Cerrar el descriptor libera flock automáticamente.
        # EN: Closing the descriptor automatically releases flock.
        lock_handle.close()


if __name__ == '__main__':
    main()
