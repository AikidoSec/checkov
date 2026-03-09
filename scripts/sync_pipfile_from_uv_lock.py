#!/usr/bin/env python3
"""
Write Pipfile from uv.lock with every dependency (including transitive) pinned.
This makes `pipenv lock` fast because there is nothing to resolve.
Run from repo root. Requires: uv.
"""
import subprocess
import sys
from pathlib import Path


def get_pinned_requirements() -> list[tuple[str, str]]:
    """Run uv export (default + dev) and return list of (package_spec, marker_or_empty)."""
    repo = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            "uv", "export", "--all-extras",
            "--format", "requirements-txt",
            "--no-header", "--no-annotate", "--no-emit-project", "--no-hashes",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    out: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip().rstrip("\\").strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        parts = line.split(None, 1)
        spec = parts[0].rstrip("\\")
        if "==" not in spec:
            continue
        name = spec.split("==")[0].split("[")[0].lower()
        if name == "checkov":
            continue
        raw = parts[1].strip() if len(parts) > 1 else ""
        marker = raw.lstrip(";").strip() if raw.startswith(";") else ""
        out.append((spec, marker))
    return out


def pipfile_line(spec: str, marker: str) -> str:
    """One Pipfile line: name = value (pinned, with optional marker)."""
    name = spec.split("==")[0]
    ver = spec.split("==", 1)[1].split()[0] if "==" in spec else ""
    if marker:
        return f'{name} = {{version = "=={ver}", markers = "{marker}"}}'
    return f'{name} = {{version = "=={ver}"}}'


def main() -> None:
    repo = Path(__file__).resolve().parent.parent
    python_version = "3.14"  # match pyproject / uv.lock
    reqs = get_pinned_requirements()
    by_name = {spec.split("==")[0].lower(): (spec, m) for spec, m in reqs}
    lines = [
        "[[source]]",
        'name = "pypi"',
        'url = "https://pypi.org/simple"',
        "verify_ssl = true",
        "",
        "# Full transitive deps from uv.lock (pinned so pipenv lock is fast)",
        "[packages]",
        *[pipfile_line(spec, m) for _, (spec, m) in sorted(by_name.items())],
        "",
        "[requires]",
        f'python_version = "{python_version}"',
        "",
    ]
    (repo / "Pipfile").write_text("\n".join(lines))
    print(f"Wrote Pipfile with {len(by_name)} pinned packages (from uv.lock)", file=sys.stderr)


if __name__ == "__main__":
    main()