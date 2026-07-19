#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
MODE="${1:-non_destructive}"
MODULE="${2:-all}"

case "$MODE" in
  non_destructive|safe)
    export PRAESIDIUM_TEST_MODULE="$MODULE"
    exec "$PYTHON_BIN" "$ROOT_DIR/fastApi/tests/run_non_destructive.py"
    ;;
  destructive)
    export PRAESIDIUM_TEST_MODULE="$MODULE"
    exec "$PYTHON_BIN" "$ROOT_DIR/fastApi/tests/run_destructive.py"
    ;;
  module)
    if [ "$MODULE" = "all" ]; then
      echo "Usage: $0 module <module_name>" >&2
      exit 2
    fi
    export PRAESIDIUM_TEST_MODULE="$MODULE"
    "$PYTHON_BIN" "$ROOT_DIR/fastApi/tests/run_non_destructive.py"
    ;;
  *)
    echo "Usage: $0 {non_destructive|destructive|module <module_name>}" >&2
    exit 2
    ;;
esac
