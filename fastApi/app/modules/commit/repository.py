"""Repositorio del módulo Commit."""

from __future__ import annotations

from pathlib import Path

from storage.paths import CANDIDATE_DIR, COMMITS_DIR, RUNNING_DIR, SCRIPTS_DIR

COMMIT_APPLY = SCRIPTS_DIR / "commits" / "commit_apply.py"


def candidate_dir() -> Path:
    return CANDIDATE_DIR


def running_dir() -> Path:
    return RUNNING_DIR


def commits_dir() -> Path:
    return COMMITS_DIR


def commit_apply_path() -> Path:
    return COMMIT_APPLY
