from __future__ import annotations

import json
from pathlib import Path

import pytest

from checkov.common.images.image_inventory import (
    AIKIDO_IMAGES_OUTPUT_ENV,
    IMAGE_INVENTORY_FILE_NAME,
    build_image_inventory,
    get_image_inventory_path,
    image_inventory_enabled,
    image_to_inventory_entry,
    write_image_inventory,
)
from checkov.common.images.image_referencer import Image


@pytest.mark.parametrize("value", ["true", "True", "TRUE", "1", " true "])
def test_enabled_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(AIKIDO_IMAGES_OUTPUT_ENV, value)

    assert image_inventory_enabled() is True
    assert get_image_inventory_path() == IMAGE_INVENTORY_FILE_NAME


@pytest.mark.parametrize("value", ["", "false", "0", "no", "off", "yes", "on", "/some/path/images.json", "anything"])
def test_disabled_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(AIKIDO_IMAGES_OUTPUT_ENV, value)

    assert image_inventory_enabled() is False
    assert get_image_inventory_path() is None


def test_disabled_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AIKIDO_IMAGES_OUTPUT_ENV, raising=False)

    assert image_inventory_enabled() is False
    assert get_image_inventory_path() is None


def test_entry_relativizes_path_and_strips_resource_id_prefix() -> None:
    image = Image(
        file_path="/repo/charts/app/templates/deployment.yaml",
        name="envoyproxy/envoy:v1.28.0",
        start_line=3,
        end_line=18,
        related_resource_id="/repo/charts/app/templates/deployment.yaml:Deployment.default.app",
    )

    entry = image_to_inventory_entry(image, framework="helm", root_folder="/repo")

    assert entry == {
        "name": "envoyproxy/envoy:v1.28.0",
        "file_path": "charts/app/templates/deployment.yaml",
        "start_line": 3,
        "end_line": 18,
        "resource_id": "Deployment.default.app",
        "framework": "helm",
    }


def test_entry_keeps_path_outside_root_and_without_root() -> None:
    image = Image(file_path="/elsewhere/pod.yaml", name="nginx", start_line=1, end_line=5, related_resource_id="x:Pod.default.p")

    assert image_to_inventory_entry(image, "kubernetes", "/repo")["file_path"] == "/elsewhere/pod.yaml"
    assert image_to_inventory_entry(image, "kubernetes", None)["file_path"] == "/elsewhere/pod.yaml"
    # unrelated related_resource_id is passed through untouched
    assert image_to_inventory_entry(image, "kubernetes", None)["resource_id"] == "x:Pod.default.p"


def test_entry_without_related_resource_id() -> None:
    image = Image(file_path="pod.yaml", name="nginx", start_line=1, end_line=5)

    assert image_to_inventory_entry(image, "kubernetes", None)["resource_id"] is None


def test_build_image_inventory_dedupes_and_sorts() -> None:
    def img(name: str, path: str = "/repo/a.yaml", resource: str = "Deployment.default.app") -> Image:
        return Image(file_path=path, name=name, start_line=1, end_line=2, related_resource_id=f"{path}:{resource}")

    images_by_framework = {
        "kubernetes": [img("nginx:1.16.0"), img("nginx:1.16.0"), img("busybox:1.28", path="/repo/b.yaml", resource="CronJob.default.c")],
        "helm": [img("nginx:1.16.0", path="/repo/charts/x/templates/d.yaml")],
    }

    entries = build_image_inventory(images_by_framework, "/repo")

    assert [(e["name"], e["framework"], e["file_path"]) for e in entries] == [
        ("busybox:1.28", "kubernetes", "b.yaml"),
        ("nginx:1.16.0", "helm", "charts/x/templates/d.yaml"),
        ("nginx:1.16.0", "kubernetes", "a.yaml"),
    ]


def test_write_image_inventory_creates_parent_dirs(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / IMAGE_INVENTORY_FILE_NAME
    entries = [{"name": "nginx:1.16.0", "file_path": "a.yaml", "start_line": 1, "end_line": 2, "resource_id": None, "framework": "kubernetes"}]

    write_image_inventory(str(target), entries)

    assert json.loads(target.read_text()) == {"images": entries}


def test_write_image_inventory_does_not_raise_on_failure(tmp_path: Path) -> None:
    # a directory where the file should be -> open() fails, must be swallowed
    target = tmp_path / IMAGE_INVENTORY_FILE_NAME
    target.mkdir()

    write_image_inventory(str(target), [])
