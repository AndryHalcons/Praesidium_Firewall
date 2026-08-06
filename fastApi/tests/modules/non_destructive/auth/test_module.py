"""Tests no destructivos de auth. / Non-destructive auth tests."""
from __future__ import annotations

import jwt

from common.runner import call


def ok(status: int) -> bool:
    return 200 <= status <= 299


def run(ctx) -> None:
    ctx.log("=== AUTH NON-DESTRUCTIVE SAME FLOW ===")
    status, payload = call(ctx, "read current user", "GET", "/api/v1/auth/me")
    ctx.log(f"CHECK current user status={status} success={ok(status)}")
    if isinstance(payload, dict):
        ctx.log(f"CHECK current user_name={payload.get('user_name')} role={payload.get('user_role')} exposes_user_pass={'user_pass' in payload}")

    token_payload = jwt.decode(ctx.token, options={"verify_signature": False})
    ttl_minutes = int((int(token_payload.get("exp", 0)) - int(token_payload.get("iat", 0))) / 60)
    ctx.log(f"CHECK token ttl minutes={ttl_minutes} expected=480 ok={ttl_minutes == 480}")
    ctx.log(f"CHECK token has_jti={bool(token_payload.get('jti'))}")
