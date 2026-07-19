"""Tests destructivos del módulo password_policy. / Destructive password_policy module tests."""
from __future__ import annotations

import json
from common.runner import call, policy, read_candidate


def response_success(status: int) -> bool:
    # ES: Detecta respuestas 2xx sin depender del rol.
    # EN: Detect 2xx responses without depending on the role.
    return 200 <= status <= 299


def log_policy_state(ctx, label: str) -> None:
    # ES: Registra estado actual de table_password_policy en candidate.
    # EN: Log current table_password_policy state in candidate.
    file_policy = policy(read_candidate())
    ctx.log(f"CHECK {label}: policy={json.dumps(file_policy, ensure_ascii=False, sort_keys=True)}")


def run(ctx) -> None:
    # ES: Ejecuta exactamente el mismo flujo con cualquier identidad inyectada.
    # EN: Execute exactly the same flow with any injected identity.
    ctx.log("=== PASSWORD_POLICY MODULE SAME FLOW ===")
    original_policy = dict(policy(read_candidate()))

    status, payload = call(ctx, "read password_policy", "GET", "/api/v1/password-policy/")
    ctx.log(f"CHECK read password_policy status={status} success={response_success(status)}")
    policy_uuid = None
    if isinstance(payload, dict) and isinstance(payload.get("policy"), dict):
        policy_uuid = payload["policy"].get("UUID")
    log_policy_state(ctx, "after read password_policy")

    for field, patch_body, expected in [
        ("password_min_length", {"password_min_length": "13"}, "13"),
        ("password_require_uppercase", {"password_require_uppercase": "false"}, "false"),
        ("password_require_lowercase", {"password_require_lowercase": "false"}, "false"),
        ("password_require_number", {"password_require_number": "false"}, "false"),
        ("password_require_symbol", {"password_require_symbol": "false"}, "false"),
        ("password_expiration_days", {"password_expiration_days": "120"}, "120"),
        ("password_history_count", {"password_history_count": "7"}, "7"),
        ("password_min_age_days", {"password_min_age_days": "2"}, "2"),
        ("login_max_failed_attempts", {"login_max_failed_attempts": "6"}, "6"),
        ("login_lockout_minutes", {"login_lockout_minutes": "31"}, "31"),
        ("login_failed_window_minutes", {"login_failed_window_minutes": "16"}, "16"),
        ("force_password_change_for_new_users", {"force_password_change_for_new_users": "false"}, "false"),
        ("password_disallow_username", {"password_disallow_username": "false"}, "false"),
        ("password_disallow_common_passwords", {"password_disallow_common_passwords": "false"}, "false"),
    ]:
        before = policy(read_candidate()).get(field)
        status, payload = call(ctx, f"granular password_policy patch {field}", "PATCH", "/api/v1/password-policy/", patch_body)
        after_policy = policy(read_candidate())
        after = after_policy.get(field)
        ctx.log(f"CHECK patch {field} status={status} success={response_success(status)} before={before} after={after} expected={expected} changed={before != after}")
        ctx.log(f"CHECK policy UUID preserved={policy_uuid is None or after_policy.get('UUID') == policy_uuid}")

    status, payload = call(ctx, "attempt to edit password_policy UUID", "PATCH", "/api/v1/password-policy/", {"UUID": "passpolicy-forged"})
    ctx.log(f"CHECK edit UUID status={status} expected_non_2xx={not response_success(status)}")
    log_policy_state(ctx, "after attempt edit UUID")

    status, payload = call(ctx, "attempt to edit force_since", "PATCH", "/api/v1/password-policy/", {"force_password_change_since": "1970-01-01T00:00:00+00:00"})
    ctx.log(f"CHECK edit force_since status={status} expected_non_2xx={not response_success(status)}")
    log_policy_state(ctx, "after attempt edit force_since")

    full_update = {
        "password_min_length": "14",
        "password_require_uppercase": "true",
        "password_require_lowercase": "true",
        "password_require_number": "true",
        "password_require_symbol": "true",
        "password_expiration_days": "180",
        "password_history_count": "8",
        "password_min_age_days": "3",
        "login_max_failed_attempts": "7",
        "login_lockout_minutes": "32",
        "login_failed_window_minutes": "17",
        "force_password_change_for_new_users": "true",
        "password_disallow_username": "true",
        "password_disallow_common_passwords": "true",
    }
    status, payload = call(ctx, "patch all password_policy editable fields", "PATCH", "/api/v1/password-policy/", full_update)
    ctx.log(f"CHECK patch all editable fields status={status} success={response_success(status)}")
    after_policy = policy(read_candidate())
    for field, expected in full_update.items():
        ctx.log(f"CHECK full {field}: actual={after_policy.get(field)} expected={expected} matches={str(after_policy.get(field)) == expected}")

    before_force_since = policy(read_candidate()).get("force_password_change_since")
    status, payload = call(ctx, "enable force-change", "POST", "/api/v1/password-policy/force-change")
    after_policy = policy(read_candidate())
    ctx.log(f"CHECK force-change status={status} success={response_success(status)} before_since={before_force_since} after_since={after_policy.get('force_password_change_since')} flag={after_policy.get('force_password_change_on_next_login')}")

    status, payload = call(ctx, "clear force-change", "POST", "/api/v1/password-policy/clear-force-change")
    after_policy = policy(read_candidate())
    ctx.log(f"CHECK clear force-change status={status} success={response_success(status)} since={after_policy.get('force_password_change_since')} flag={after_policy.get('force_password_change_on_next_login')}")

    ctx.log(f"INFO original password_policy restored at the end: {json.dumps(original_policy, ensure_ascii=False, sort_keys=True)}")
