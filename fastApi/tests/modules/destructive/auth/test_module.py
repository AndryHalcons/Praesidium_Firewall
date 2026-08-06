"""Tests destructivos de auth/lockout. / Destructive auth/lockout tests."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import jwt

from common.runner import RUNNING, call, call_with_token


def ok(status: int) -> bool:
    return 200 <= status <= 299


def _prepare_lockout_fixture(ctx) -> str:
    # ES: Ajusta running temporalmente para lockout rápido; el orquestador restaura.
    # EN: Temporarily tune running for fast lockout; the orchestrator restores it.
    data = json.loads(RUNNING.read_text(encoding="utf-8"))
    policy = data.get("table_password_policy", [{}])[0]
    policy["login_max_failed_attempts"] = "2"
    policy["login_lockout_minutes"] = "1"
    policy["login_failed_window_minutes"] = "15"
    data["table_login_attempts"] = []
    RUNNING.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
    ctx.log("CHECK lockout fixture prepared")
    return ctx.identity.username


def run(ctx) -> None:
    ctx.log("=== AUTH DESTRUCTIVE SAME FLOW ===")

    status, payload = call(ctx, "current user with valid token", "GET", "/api/v1/auth/me")
    ctx.log(f"CHECK valid token me status={status} success={ok(status)}")

    status, payload = call_with_token(ctx, "current user without token", "GET", "/api/v1/auth/me", token=None)
    ctx.log(f"CHECK missing token status={status} expected_non_2xx={not ok(status)} detail={payload.get('detail') if isinstance(payload, dict) else payload}")

    status, payload = call_with_token(ctx, "current user with malformed token", "GET", "/api/v1/auth/me", token="not-a-valid-jwt")
    ctx.log(f"CHECK malformed token status={status} expected_non_2xx={not ok(status)} detail={payload.get('detail') if isinstance(payload, dict) else payload}")

    now_ts = int(datetime.now(timezone.utc).timestamp())
    expired_token = jwt.encode({
        "sub": ctx.identity.username,
        "role": ctx.identity.role,
        "lang": ctx.identity.language,
        "iat": now_ts - 7200,
        "exp": now_ts - 3600,
        "jti": uuid4().hex,
    }, Path("/var/lib/praesidium/state/api_token_secret").read_text(encoding="utf-8").strip(), algorithm="HS256")
    status, payload = call_with_token(ctx, "expired token is rejected", "GET", "/api/v1/auth/me", token=expired_token)
    ctx.log(f"CHECK expired token status={status} expected_401={status == 401} detail={payload.get('detail') if isinstance(payload, dict) else payload}")

    username = _prepare_lockout_fixture(ctx)
    status, payload = call_with_token(ctx, "bad login 1", "POST", "/api/v1/auth/login", {"username": username, "password": "WrongPassword123A*"}, token=None)
    ctx.log(f"CHECK bad login 1 status={status} expected_non_2xx={not ok(status)}")

    status, payload = call_with_token(ctx, "bad login 2", "POST", "/api/v1/auth/login", {"username": username, "password": "WrongPassword123A*"}, token=None)
    ctx.log(f"CHECK bad login 2 status={status} expected_non_2xx={not ok(status)}")

    status, payload = call_with_token(ctx, "login while locked", "POST", "/api/v1/auth/login", {"username": f"{username}_locked_probe", "password": ctx.current_password}, token=None)
    ctx.log(f"CHECK login locked status={status} expected_429={status == 429}")

    status, payload = call(ctx, "list login attempts", "GET", "/api/v1/login-attempts/")
    attempts = payload.get("attempts", []) if isinstance(payload, dict) and isinstance(payload.get("attempts"), list) else []
    attempts_count = len(attempts)
    unlock_ip = attempts[0].get("client_ip", "127.0.0.1") if attempts else "127.0.0.1"
    usernames = attempts[0].get("usernames", "") if attempts else ""
    ctx.log(f"CHECK login attempts list status={status} attempts_count={attempts_count} unlock_ip={unlock_ip} usernames={usernames} has_original={username in usernames} has_locked_probe={(username + '_locked_probe') in usernames}")

    status, payload = call(ctx, "unlock own source ip", "DELETE", f"/api/v1/login-attempts/{unlock_ip}")
    ctx.log(f"CHECK unlock login attempts status={status} detail={payload.get('detail') if isinstance(payload, dict) else payload}")

    status, payload = call_with_token(ctx, "login after unlock attempt", "POST", "/api/v1/auth/login", {"username": username, "password": ctx.current_password}, token=None)
    ctx.log(f"CHECK login after unlock status={status} success={ok(status)}")

    status, payload = call(ctx, "logout revokes current token", "POST", "/api/v1/auth/logout")
    ctx.log(f"CHECK logout status={status} success={ok(status)}")

    status, payload = call(ctx, "current user with revoked token", "GET", "/api/v1/auth/me")
    ctx.log(f"CHECK revoked token status={status} expected_401={status == 401} detail={payload.get('detail') if isinstance(payload, dict) else payload}")
