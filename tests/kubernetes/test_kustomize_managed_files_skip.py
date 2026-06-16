import os
import unittest

from checkov.common.runners.runner_registry import RunnerRegistry
from checkov.kubernetes.checks.resource.k8s.ContainerSecurityContext import check
from checkov.kubernetes.runner import Runner as KubernetesRunner
from checkov.kustomize.runner import (
    Runner as KustomizeRunner,
    filter_kubernetes_report_for_kustomize_dirs,
    find_kustomize_directories,
)
from checkov.kubernetes.runner import Runner
from checkov.runner_filter import RunnerFilter

EXAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "kustomize",
    "runner",
    "resources",
    "example",
)


class TestKustomizeManagedFilesSkip(unittest.TestCase):
    def test_post_processing_removes_kubernetes_findings_under_kustomize_dirs(self):
        root = os.path.abspath(EXAMPLE)
        runner_filter = RunnerFilter(framework=["kubernetes", "kustomize"], checks=[check.id])
        registry = RunnerRegistry("", runner_filter, KubernetesRunner(), KustomizeRunner())
        reports = registry.run(root_folder=root)

        kubernetes_report = next(report for report in reports if report.check_type == "kubernetes")
        failed_files = {record.file_abs_path for record in kubernetes_report.failed_checks}
        managed_deployment = os.path.abspath(os.path.join(root, "base", "deployment.yaml"))
        self.assertNotIn(managed_deployment, failed_files)

    def test_kubernetes_runner_still_scans_kustomize_dirs_before_post_processing(self):
        root = os.path.abspath(EXAMPLE)
        runner = Runner()
        report = runner.run(
            root_folder=root,
            runner_filter=RunnerFilter(framework=["kubernetes"], checks=[check.id]),
        )

        failed_files = {record.file_abs_path for record in report.failed_checks}
        managed_deployment = os.path.abspath(os.path.join(root, "base", "deployment.yaml"))
        self.assertIn(managed_deployment, failed_files)

    def test_filter_kubernetes_report_for_kustomize_dirs(self):
        root = os.path.abspath(EXAMPLE)
        runner = Runner()
        report = runner.run(
            root_folder=root,
            runner_filter=RunnerFilter(framework=["kubernetes"], checks=[check.id]),
        )
        self.assertTrue(report.failed_checks)

        managed_directories: set[str] = set()
        find_kustomize_directories(root, None, [], managed_directories)
        filter_kubernetes_report_for_kustomize_dirs(report, managed_directories)

        failed_files = {record.file_abs_path for record in report.failed_checks}
        managed_deployment = os.path.abspath(os.path.join(root, "base", "deployment.yaml"))
        self.assertNotIn(managed_deployment, failed_files)


if __name__ == "__main__":
    unittest.main()
