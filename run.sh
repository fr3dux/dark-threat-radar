#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ -f "$DIR/venv/bin/python3" ]; then
    PYTHON="$DIR/venv/bin/python3"
else
    PYTHON="python3"
fi

if [ ! -f "$DIR/.env" ]; then
    echo "Missing .env configuration. Run: $PYTHON scripts/setup_admin.py" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1091
. "$DIR/.env"
set +a

if [ -z "${SETTINGS_ADMIN_TOKEN:-}" ]; then
    echo "SETTINGS_ADMIN_TOKEN is empty. Run: $PYTHON scripts/setup_admin.py" >&2
    exit 1
fi

export PYTHONPATH="${PYTHONPATH:-$DIR}"

exec "$PYTHON" -m uvicorn app.main:app --host "${HOST:-0.0.0.0}" --port "${PORT:-9220}"
