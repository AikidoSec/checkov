from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.images.image_inventory import AIKIDO_IMAGES_OUTPUT_ENV, IMAGE_INVENTORY_FILE_NAME
from checkov.common.images.image_referencer import Image
from checkov.common.runners.runner_registry import RunnerRegistry
from checkov.common.util.banner import banner
from checkov.helm.runner import Runner as helm_runner
from checkov.kubernetes.runner import Runner as k8s_runner
from checkov.runner_filter import RunnerFilter
from tests.helm.utils import helm_exists

K8S_RESOURCES = Path(__file__).parent.parent.parent / "kubernetes/image_referencer/resources/k8s"
HELM_CHART = Path(__file__).parent.parent.parent / "helm/runner/resources/image_referencer"


def _read_inventory(cwd: Path) -> list[dict]:
    return json.loads((cwd / IMAGE_INVENTORY_FILE_NAME).read_text())["images"]


def test_kubernetes_single_runner_writes_inventory_in_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # given: a repo with one plain k8s manifest, and the toggle on
    repo = tmp_path / "repo"
    (repo / "k8s").mkdir(parents=True)
    shutil.copy(K8S_RESOURCES / "cron_job.yaml", repo / "k8s" / "cron_job.yaml")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv(AIKIDO_IMAGES_OUTPUT_ENV, "true")

    # when: single-runner path (no fork)
    registry = RunnerRegistry(banner, RunnerFilter(framework=[CheckType.KUBERNETES]), k8s_runner())
    registry.run(root_folder=str(repo))

    # then: results_images.json is next to where results.sarif would go
    entries = _read_inventory(cwd)
    assert entries == [
        {
            "name": "busybox:1.28",
            "file_path": "k8s/cron_job.yaml",
            "start_line": entries[0]["start_line"],
            "end_line": entries[0]["end_line"],
            "resource_id": "CronJob.default.hello",
            "framework": CheckType.KUBERNETES,
        }
    ]


@pytest.mark.skipif(not helm_exists(), reason="helm not installed")
def test_helm_and_kubernetes_parallel_runners_write_merged_inventory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # given: a helm chart with a templated image plus a plain manifest, two runners -> forked parallel path
    repo = tmp_path / "repo"
    # directory name must match the chart name in Chart.yaml, like a real repo would;
    # helm's "# Source:" lines use the chart name and checkov strips it only if the dir matches
    shutil.copytree(HELM_CHART, repo / "charts" / "hello-world")
    (repo / "k8s").mkdir()
    shutil.copy(K8S_RESOURCES / "cron_job.yaml", repo / "k8s" / "cron_job.yaml")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv(AIKIDO_IMAGES_OUTPUT_ENV, "true")

    # when
    registry = RunnerRegistry(
        banner, RunnerFilter(framework=[CheckType.HELM, CheckType.KUBERNETES]), helm_runner(), k8s_runner()
    )
    registry.run(root_folder=str(repo))

    # then: the "{{ .Values.image.repository }}:{{ .Values.image.tag }}" reference comes back resolved
    entries = _read_inventory(cwd)
    by_framework = {(e["framework"], e["name"]): e for e in entries}

    helm_entry = by_framework[(CheckType.HELM, "nginx:1.16.0")]
    assert helm_entry["file_path"] == "charts/hello-world/templates/deployment.yaml"
    assert helm_entry["resource_id"].startswith("Pod.default.release-name-")

    k8s_entry = by_framework[(CheckType.KUBERNETES, "busybox:1.28")]
    assert k8s_entry["file_path"] == "k8s/cron_job.yaml"
    assert k8s_entry["resource_id"] == "CronJob.default.hello"


def test_nothing_written_when_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(K8S_RESOURCES / "cron_job.yaml", repo / "cron_job.yaml")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv(AIKIDO_IMAGES_OUTPUT_ENV, raising=False)

    registry = RunnerRegistry(banner, RunnerFilter(framework=[CheckType.KUBERNETES]), k8s_runner())
    registry.run(root_folder=str(repo))

    assert not (cwd / IMAGE_INVENTORY_FILE_NAME).exists()
    assert registry.image_inventory == []


def test_multiple_root_folders_accumulate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # main.py calls registry.run() once per "-d"; every call must rewrite the file with everything so far,
    # each entry relative to the root folder it was scanned under
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv(AIKIDO_IMAGES_OUTPUT_ENV, "true")
    registry = RunnerRegistry(banner, RunnerFilter(framework=[CheckType.KUBERNETES]), k8s_runner())

    def image(root: str, rel: str, name: str) -> Image:
        path = f"{root}/{rel}"
        return Image(file_path=path, name=name, start_line=1, end_line=2, related_resource_id=f"{path}:Pod.default.p")

    registry._write_image_inventory({CheckType.KUBERNETES: [image("/repo/a", "cron_job.yaml", "busybox:1.28")]}, "/repo/a")
    assert {e["file_path"] for e in _read_inventory(cwd)} == {"cron_job.yaml"}

    registry._write_image_inventory({CheckType.KUBERNETES: [image("/repo/b", "pod.yaml", "nginx:latest")]}, "/repo/b")
    assert {(e["file_path"], e["name"]) for e in _read_inventory(cwd)} == {
        ("cron_job.yaml", "busybox:1.28"),
        ("pod.yaml", "nginx:latest"),
    }
