import unittest
from pathlib import Path

from checkov.common.models.enums import CheckResult
from checkov.kubernetes.checks.resource.k8s.ContainerSecurityContext import check
from checkov.kubernetes.runner import Runner
from checkov.runner_filter import RunnerFilter


class TestContainerSecurityContext(unittest.TestCase):
    def test_summary(self):
        checks_dir = Path(__file__).parent
        files = sorted(
            str(path)
            for folder in ("example_SecurityContexts", "example_ContainerSecurityContext")
            for path in (checks_dir / folder).glob("*.yaml")
        )

        report = Runner().run(root_folder="", files=files, runner_filter=RunnerFilter(checks=[check.id]))
        summary = report.get_summary()

        passing_resources = {
            "Pod.default.security-context-demo",
            "Pod.default.pod-drop-net-raw-capability",
            "Deployment.default.linux-nodeselector-with-securitycontext",
        }
        failing_resources = {
            "ReplicaSet.default.frontend",
            "CronJob.default.hello",
            "Deployment.default.linux-nodeselector-still-fail",
            "Pod.default.linux-os-name-still-fail",
            "Deployment.default.preferred-affinity-windows-still-fail",
            "Deployment.default.runtimeclass-windows-still-fail",
            "Deployment.default.toleration-windows-still-fail",
            "Deployment.default.affinity-or-windows-linux-still-fail",
            "Deployment.default.affinity-notin-linux-still-fail",
            "Deployment.default.affinity-os-doesnotexist-still-fail",
            "Deployment.default.null-nodeselector-still-fail",
        }
        unknown_resources = {
            "Deployment.default.win-webserver-nodeselector",
            "Pod.default.win-pod-os-name",
            "StatefulSet.default.win-statefulset-affinity",
            "DaemonSet.default.win-daemonset-beta-os",
            "Job.default.win-job-combined",
            "CronJob.default.win-cronjob-nodeselector",
            "Deployment.default.win-with-securitycontext",
            "Deployment.default.win-affinity-matchfields",
            "Deployment.default.win-nodeselector-case-insensitive",
            "Deployment.default.win-pod-level-securitycontext",
        }
        unknown_graph_pods = {
            "Pod.default.win-webserver-nodeselector.app-win-webserver",
            "Pod.default.win-statefulset-affinity.app-win-sts",
            "Pod.default.win-daemonset-beta-os.app-win-ds",
            "Pod.default.win-with-securitycontext.app-win-sc",
            "Pod.default.win-affinity-matchfields.app-win-fields",
            "Pod.default.win-nodeselector-case-insensitive.app-win-case",
            "Pod.default.win-pod-level-securitycontext.app-win-pod-sc",
            "Pod.default.win-job-combined.app-win-job",
        }

        passed_check_resources = {c.resource for c in report.passed_checks}
        failed_check_resources = {c.resource for c in report.failed_checks}

        self.assertEqual(summary["passed"], len(passing_resources))
        self.assertEqual(summary["failed"], len(failing_resources))
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["parsing_errors"], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)

        for resource in unknown_resources | unknown_graph_pods:
            self.assertNotIn(resource, passed_check_resources)
            self.assertNotIn(resource, failed_check_resources)

        self.assertTrue(any("win-cronjob-nodeselector" in r for r in report.resources))
        for resource in passed_check_resources | failed_check_resources:
            self.assertNotIn("win-cronjob-nodeselector", resource)

    def test_nested_pod_spec_extraction_for_workload_kinds(self):
        deployment = {
            "kind": "Deployment",
            "metadata": {"name": "win-nested"},
            "spec": {
                "replicas": 1,
                "template": {
                    "metadata": {},
                    "spec": {
                        "nodeSelector": {"kubernetes.io/os": "windows"},
                        "containers": [{"name": "c", "image": "busybox"}],
                    },
                },
            },
        }
        cronjob = {
            "kind": "CronJob",
            "metadata": {"name": "win-cron"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "metadata": {},
                            "spec": {
                                "os": {"name": "windows"},
                                "containers": [{"name": "c", "image": "busybox"}],
                            },
                        }
                    }
                }
            },
        }

        check.entity_type = "Deployment"
        self.assertEqual(check.scan_spec_conf(deployment), CheckResult.UNKNOWN)

        check.entity_type = "CronJob"
        self.assertEqual(check.scan_spec_conf(cronjob), CheckResult.UNKNOWN)

        cronjob_root_only = {
            "kind": "CronJob",
            "metadata": {"name": "win-cron-root"},
            "spec": {
                "schedule": "*/5 * * * *",
                "nodeSelector": {"kubernetes.io/os": "windows"},
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "metadata": {},
                            "spec": {
                                "containers": [{"name": "c", "image": "busybox"}],
                            },
                        }
                    }
                },
            },
        }
        check.entity_type = "CronJob"
        self.assertEqual(check.scan_spec_conf(cronjob_root_only), CheckResult.FAILED)

        linux_deployment = {
            "kind": "Deployment",
            "metadata": {"name": "linux-nested"},
            "spec": {
                "template": {
                    "metadata": {},
                    "spec": {
                        "nodeSelector": {"kubernetes.io/os": "linux"},
                        "containers": [{"name": "c", "image": "busybox"}],
                    },
                }
            },
        }
        check.entity_type = "Deployment"
        self.assertEqual(check.scan_spec_conf(linux_deployment), CheckResult.FAILED)


if __name__ == "__main__":
    unittest.main()
