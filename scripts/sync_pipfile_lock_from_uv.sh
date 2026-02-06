#!/usr/bin/env bash
# Update Pipfile and Pipfile.lock from uv.lock.
# Writes full transitive pinned Pipfile so `pipenv lock` is fast (no resolution).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

echo "Writing full pinned Pipfile from uv.lock..." >&2
uv run python "$REPO/scripts/sync_pipfile_from_uv_lock.py" 2>/dev/null || python3 "$REPO/scripts/sync_pipfile_from_uv_lock.py"

echo "Running pipenv lock (no resolution needed; should be fast)..." >&2
export PIPENV_IGNORE_VIRTUALENVS=1
pipenv lock

echo "Pipfile and Pipfile.lock updated." >&2
