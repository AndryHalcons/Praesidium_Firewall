#!/usr/bin/env python3
"""Orquestador de tests destructivos FastAPI. / FastAPI destructive test orchestrator."""
from __future__ import annotations
import sys
from pathlib import Path
TESTS_ROOT = Path(__file__).resolve().parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))
from common.runner import run_mode
from common.test_identities import TEST_IDENTITIES
if __name__ == "__main__":
    raise SystemExit(run_mode(TESTS_ROOT, "destructive", TEST_IDENTITIES))
