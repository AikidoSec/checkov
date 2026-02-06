#!/usr/bin/env python3
"""
Update setup.py install_requires from uv.lock (full transitive pinned list).
Run from repo root. Requires: uv export (writes requirements to stdout or file).
"""
import re
import subprocess
import sys
from pathlib import Path


def get_pinned_requirements() -> list[str]:
    """Run uv export and return list of 'package==version' (no hashes, no project)."""
    repo = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        ["uv", "export", "--format", "requirements-txt", "--no-header", "--no-annotate", "--no-emit-project", "--no-hashes"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    lines = []
    for line in result.stdout.splitlines():
        line = line.strip().rstrip("\\").strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        # spec is package==version or "package==version ; marker"
        parts = line.split(None, 1)
        spec = parts[0].rstrip("\\")
        if "==" not in spec:
            continue
        name = spec.split("==")[0].split("[")[0].lower()
        if name == "checkov":
            continue
        if len(parts) > 1 and parts[1].strip().startswith(";"):
            spec = f"{spec} {parts[1].strip()}"
        lines.append(spec)
    return lines


def update_setup_py(install_requires: list[str]) -> None:
    repo = Path(__file__).resolve().parent.parent
    path = repo / "setup.py"
    text = path.read_text()
    start_marker = "install_requires=["
    idx = text.find(start_marker)
    if idx == -1:
        print("install_requires= not found in setup.py", file=sys.stderr)
        sys.exit(1)
    start = idx + len(start_marker)
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
        i += 1
    end = i - 1
    new_content = ",\n        ".join(repr(req) for req in install_requires)
    new_block = f"install_requires=[\n        {new_content}\n    ]"
    new_text = text[:idx] + new_block + text[end + 1 :]
    path.write_text(new_text)
    print(f"Updated {path} with {len(install_requires)} pinned dependencies", file=sys.stderr)


def main() -> None:
    install_requires = get_pinned_requirements()
    if not install_requires:
        print("No requirements from uv export", file=sys.stderr)
        sys.exit(1)
    update_setup_py(install_requires)


if __name__ == "__main__":
    main()
