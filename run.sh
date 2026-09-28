#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

export PYTHONPATH="${PYTHONPATH:-$DIR}"

if [ -f "$DIR/venv/bin/python3" ]; then
    PYTHON="$DIR/venv/bin/python3"
else
    PYTHON="python3"
fi

exec "$PYTHON" -m uvicorn app.main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-9220}"
