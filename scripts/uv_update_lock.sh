#!/usr/bin/env bash
# Refresh uv.lock and sync setup.py, Pipfile, Pipfile.lock.
# Run after editing pyproject.toml (add/remove/change deps).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

echo "Running uv lock..." >&2
uv lock

echo "Syncing setup.py from uv.lock..." >&2
uv run python scripts/sync_setup_py_from_uv_lock.py

echo "Syncing Pipfile and Pipfile.lock from uv.lock..." >&2
"$REPO/scripts/sync_pipfile_lock_from_uv.sh"

echo "Done. setup.py, Pipfile, and Pipfile.lock are in sync with pyproject.toml and uv.lock." >&2