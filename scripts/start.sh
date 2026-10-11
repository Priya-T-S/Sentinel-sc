#!/usr/bin/env sh
# One-command start (macOS/Linux): sets up the backend venv, builds the UI if needed, starts the server.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
[ -d .venv ] || { python3 -m venv .venv; .venv/bin/python -m pip install -r requirements-dev.txt; }
[ -f "$ROOT/frontend/dist/index.html" ] || (cd "$ROOT/frontend" && npm ci && npm run build)
echo "SENTINEL-SC on http://127.0.0.1:8000"
exec .venv/bin/python -m uvicorn sentinel.app:app --host 127.0.0.1 --port 8000
