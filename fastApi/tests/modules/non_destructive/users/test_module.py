"""Tests no destructivos de users. / Non-destructive users tests."""
from __future__ import annotations

from common.runner import call


def ok(status: int) -> bool:
    return 200 <= status <= 299


def contains_secret(value) -> bool:
    if isinstance(value, dict):
        return any(k == "user_pass" or contains_secret(v) for k, v in value.items())
    if isinstance(value, list):
        return any(contains_secret(v) for v in value)
    return False


def run(ctx) -> None:
    ctx.log("=== USERS NON-DESTRUCTIVE SAME FLOW ===")
    status, payload = call(ctx, "list users", "GET", "/api/v1/users/")
    ctx.log(f"CHECK list users status={status} success={ok(status)}")
    if isinstance(payload, dict):
        users = payload.get("users", [])
        ctx.log(f"CHECK users_count={len(users) if isinstance(users, list) else 'invalid'} exposes_user_pass={contains_secret(payload)}")
