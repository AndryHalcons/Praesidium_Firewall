"""Schemas de login_attempts. / login_attempts schemas."""

from __future__ import annotations

from pydantic import BaseModel


class LoginAttemptResponse(BaseModel):
    client_ip: str
    usernames: str = ""
    failed_count: str = "0"
    first_failed_at: str = ""
    locked_until: str = ""


class LoginAttemptsResponse(BaseModel):
    attempts: list[LoginAttemptResponse]


class LoginAttemptDeleteResponse(BaseModel):
    status: str
    deleted_client_ip: str
