import os
import shutil
import unittest

from checkov.kubernetes.runner import Runner as K8sRunner
from checkov.kustomize.runner import Runner as KustomizeRunner
from checkov.runner_filter import RunnerFilter
from tests.kustomize.utils import kustomize_exists


def kubectl_kustomize_exists() -> bool:
    return shutil.which("kubectl") is not None or kustomize_exists()

KUSTOMIZEGOAT_DIR = os.path.join(os.path.dirname(__file__), "runner", "resources", "kustomizegoat")

SECURITY_CHECKS = [
    "CKV_K8S_11",  # CPU limits
    "CKV_K8S_10",  # CPU requests
    "CKV_K8S_13",  # Memory limits
    "CKV_K8S_12",  # Memory requests
    "CKV_K8S_22",  # Read-only filesystem
    "CKV_K8S_20",  # AllowPrivilegeEscalation
    "CKV_K8S_9",   # Readiness probe
    "CKV_K8S_8",   # Liveness probe
]


class TestKustomizegoatWithoutKustomizeSupport(unittest.TestCase):
    """
    When scanning the base deployment.yaml with the plain Kubernetes runner
    (i.e. kustomize support is NOT enabled), the insecure base manifests are
    flagged because overlays are never applied.
    """

    def test_base_deployment_fails_security_checks(self):
        base_dir = os.path.join(KUSTOMIZEGOAT_DIR, "base")
        runner = K8sRunner()
        report = runner.run(
            root_folder=base_dir,
            runner_filter=RunnerFilter(framework=["kubernetes"], checks=SECURITY_CHECKS),
        )

        failed_check_ids = {r.check_id for r in report.failed_checks}

        for check_id in SECURITY_CHECKS:
            self.assertIn(
                check_id,
                failed_check_ids,
                f"{check_id} should FAIL on the base deployment when kustomize is not used",
            )

        self.assertEqual(len(report.passed_checks), 0)


@unittest.skipIf(os.name == "nt" or not kubectl_kustomize_exists(), "kustomize/kubectl not installed or Windows OS")
class TestKustomizegoatWithKustomizeSupport(unittest.TestCase):
    """
    When scanning with the Kustomize runner, the prod overlay patches the base
    deployment to add all security controls. The rendered manifest passes the
    same checks that the raw base fails.
    """

    def test_prod_overlay_passes_security_checks(self):
        runner = KustomizeRunner()
        runner.templateRendererCommand = "kubectl"

        report = runner.run(
            root_folder=KUSTOMIZEGOAT_DIR,
            runner_filter=RunnerFilter(framework=["kustomize"], checks=SECURITY_CHECKS),
        )

        overlay_passed = [
            r for r in report.passed_checks if "overlay" in r.resource.lower()
        ]
        overlay_failed = [
            r for r in report.failed_checks if "overlay" in r.resource.lower()
        ]

        passed_check_ids = {r.check_id for r in overlay_passed}

        for check_id in SECURITY_CHECKS:
            self.assertIn(
                check_id,
                passed_check_ids,
                f"{check_id} should PASS on the prod overlay when kustomize is enabled",
            )

        self.assertEqual(
            len(overlay_failed),
            0,
            f"No checks should fail on the prod overlay, but got: "
            f"{[(r.check_id, r.resource) for r in overlay_failed]}",
        )


if __name__ == "__main__":
    unittest.main()
