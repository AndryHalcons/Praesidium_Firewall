"""Tests no destructivos de login_attempts. / Non-destructive login_attempts tests."""
from __future__ import annotations

from common.runner import call


def ok(status: int) -> bool:
    return 200 <= status <= 299


def run(ctx) -> None:
    ctx.log("=== LOGIN_ATTEMPTS NON-DESTRUCTIVE SAME FLOW ===")
    status, payload = call(ctx, "list login attempts", "GET", "/api/v1/login-attempts/")
    attempts_count = len(payload.get("attempts", [])) if isinstance(payload, dict) and isinstance(payload.get("attempts"), list) else 0
    ctx.log(f"CHECK list login attempts status={status} success={ok(status)} attempts_count={attempts_count}")
