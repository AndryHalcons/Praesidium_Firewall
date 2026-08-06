"""Tests no destructivos de password_policy. / Non-destructive password_policy tests."""
from __future__ import annotations

from common.runner import call


def ok(status: int) -> bool:
    return 200 <= status <= 299


def run(ctx) -> None:
    ctx.log("=== PASSWORD_POLICY NON-DESTRUCTIVE SAME FLOW ===")
    status, payload = call(ctx, "read password_policy", "GET", "/api/v1/password-policy/")
    ctx.log(f"CHECK read password_policy status={status} success={ok(status)}")
    if isinstance(payload, dict):
        policy = payload.get("policy", {})
        ctx.log(f"CHECK policy_fields={len(policy) if isinstance(policy, dict) else 'invalid'}")
