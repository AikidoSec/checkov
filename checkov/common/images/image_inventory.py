"""Aikido: dump the container images referenced by the scanned IaC to a JSON file.

Checkov already renders Helm charts / Kustomize overlays and builds a Kubernetes
graph out of the result. Upstream only uses the images found in that graph to
query the Prisma vulnerability cache (gated behind ``run_image_referencer`` and a
platform licence), so without a platform key the list is thrown away.

Setting ``AIKIDO_IMAGES_OUTPUT=true`` makes the runner registry collect the
images from every runner that supports it (kubernetes, helm, kustomize) and
write them to ``results_images.json`` in the current working directory, next to
checkov's default ``results.sarif``, without any platform lookups.

File shape::

    {
      "images": [
        {
          "name": "envoyproxy/envoy:v1.28.0",
          "file_path": "charts/app/templates/deployment.yaml",
          "start_line": 3,
          "end_line": 18,
          "resource_id": "Deployment.default.app",
          "framework": "helm"
        }
      ]
    }
"""
from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from checkov.common.images.image_referencer import Image

AIKIDO_IMAGES_OUTPUT_ENV = "AIKIDO_IMAGES_OUTPUT"
# mirrors the SARIF default of "results.sarif" in the CWD
IMAGE_INVENTORY_FILE_NAME = "results_images.json"


def image_inventory_enabled() -> bool:
    return os.getenv(AIKIDO_IMAGES_OUTPUT_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def get_image_inventory_path() -> str | None:
    return IMAGE_INVENTORY_FILE_NAME if image_inventory_enabled() else None


def _relative_path(file_path: str, root_folder: str | None) -> str:
    if not file_path or not root_folder:
        return file_path
    try:
        rel = os.path.relpath(file_path, root_folder)
    except ValueError:
        # different drives on Windows
        return file_path
    if rel.startswith(os.pardir):
        return file_path
    return rel


def _resource_id(image: Image, original_file_path: str) -> str | None:
    related = image.related_resource_id
    if not related:
        return None
    # related_resource_id is usually "<file_path>:<Kind.namespace.name>"
    prefix = f"{original_file_path}:"
    if related.startswith(prefix):
        return related[len(prefix):]
    return related


def image_to_inventory_entry(image: Image, framework: str, root_folder: str | None) -> dict[str, Any]:
    return {
        "name": image.name,
        "file_path": _relative_path(image.file_path, root_folder),
        "start_line": image.start_line,
        "end_line": image.end_line,
        "resource_id": _resource_id(image, image.file_path),
        "framework": framework,
    }


def build_image_inventory(
    images_by_framework: dict[str, list[Image]], root_folder: str | None
) -> list[dict[str, Any]]:
    entries: dict[tuple[Any, ...], dict[str, Any]] = {}
    for framework, images in images_by_framework.items():
        for image in images:
            entry = image_to_inventory_entry(image, framework, root_folder)
            key = (entry["name"], entry["file_path"], entry["resource_id"], entry["framework"])
            entries.setdefault(key, entry)
    return sorted(entries.values(), key=lambda e: (e["name"], e["framework"], e["file_path"], e["resource_id"] or ""))


def write_image_inventory(path: str, entries: list[dict[str, Any]]) -> None:
    try:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"images": entries}, fh, indent=2)
        logging.info(f"Wrote {len(entries)} image references to {path}")
    except Exception:
        logging.warning(f"Failed to write image inventory to {path}", exc_info=True)
