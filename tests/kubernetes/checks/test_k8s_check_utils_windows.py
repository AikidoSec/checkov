import unittest

from checkov.kubernetes.checks.resource.k8s.k8s_check_utils import is_windows_pod_spec


def _required_affinity_terms(*terms):
    return {
        "affinity": {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": list(terms)
                }
            }
        }
    }


def _os_in_term(os_values, key="kubernetes.io/os", operator="In", matcher="matchExpressions"):
    return {
        matcher: [
            {
                "key": key,
                "operator": operator,
                "values": list(os_values),
            }
        ]
    }


class TestIsWindowsPodSpec(unittest.TestCase):
    def test_non_dict_spec_is_not_windows(self):
        self.assertFalse(is_windows_pod_spec(None))
        self.assertFalse(is_windows_pod_spec([]))
        self.assertFalse(is_windows_pod_spec("windows"))

    def test_empty_spec_is_not_windows(self):
        self.assertFalse(is_windows_pod_spec({}))

    def test_os_name_windows(self):
        self.assertTrue(is_windows_pod_spec({"os": {"name": "windows"}}))

    def test_os_name_windows_case_insensitive(self):
        self.assertTrue(is_windows_pod_spec({"os": {"name": "Windows"}}))
        self.assertTrue(is_windows_pod_spec({"os": {"name": "WINDOWS"}}))

    def test_os_name_linux(self):
        self.assertFalse(is_windows_pod_spec({"os": {"name": "linux"}}))

    def test_os_name_missing_or_malformed(self):
        self.assertFalse(is_windows_pod_spec({"os": {}}))
        self.assertFalse(is_windows_pod_spec({"os": "windows"}))
        self.assertFalse(is_windows_pod_spec({"os": [{"name": "windows"}]}))

    def test_node_selector_kubernetes_io_os_windows(self):
        self.assertTrue(
            is_windows_pod_spec({"nodeSelector": {"kubernetes.io/os": "windows"}})
        )

    def test_node_selector_windows_case_insensitive(self):
        self.assertTrue(
            is_windows_pod_spec({"nodeSelector": {"kubernetes.io/os": "Windows"}})
        )

    def test_node_selector_beta_kubernetes_io_os_windows(self):
        self.assertTrue(
            is_windows_pod_spec({"nodeSelector": {"beta.kubernetes.io/os": "windows"}})
        )

    def test_node_selector_linux_is_not_windows(self):
        self.assertFalse(
            is_windows_pod_spec({"nodeSelector": {"kubernetes.io/os": "linux"}})
        )

    def test_node_selector_other_labels_only(self):
        self.assertFalse(
            is_windows_pod_spec(
                {"nodeSelector": {"node.kubernetes.io/windows-build": "10.0.20348"}}
            )
        )

    def test_node_selector_malformed(self):
        self.assertFalse(is_windows_pod_spec({"nodeSelector": ["kubernetes.io/os=windows"]}))
        self.assertFalse(is_windows_pod_spec({"nodeSelector": "windows"}))

    def test_node_selector_list_wrapped_value(self):
        self.assertTrue(
            is_windows_pod_spec({"nodeSelector": {"kubernetes.io/os": ["windows"]}})
        )

    def test_required_affinity_in_windows(self):
        self.assertTrue(is_windows_pod_spec(_required_affinity_terms(_os_in_term(["windows"]))))

    def test_required_affinity_beta_label(self):
        self.assertTrue(
            is_windows_pod_spec(
                _required_affinity_terms(_os_in_term(["windows"], key="beta.kubernetes.io/os"))
            )
        )

    def test_required_affinity_operator_case_insensitive(self):
        self.assertTrue(
            is_windows_pod_spec(_required_affinity_terms(_os_in_term(["windows"], operator="in")))
        )
        self.assertTrue(
            is_windows_pod_spec(_required_affinity_terms(_os_in_term(["WINDOWS"], operator="IN")))
        )

    def test_required_affinity_match_fields(self):
        self.assertTrue(
            is_windows_pod_spec(
                _required_affinity_terms(_os_in_term(["windows"], matcher="matchFields"))
            )
        )

    def test_required_affinity_match_fields_and_expressions(self):
        term = {
            "matchExpressions": [
                {"key": "kubernetes.io/arch", "operator": "In", "values": ["amd64"]}
            ],
            "matchFields": [
                {"key": "kubernetes.io/os", "operator": "In", "values": ["windows"]}
            ],
        }
        self.assertTrue(is_windows_pod_spec(_required_affinity_terms(term)))

    def test_required_affinity_in_linux_is_not_windows(self):
        self.assertFalse(is_windows_pod_spec(_required_affinity_terms(_os_in_term(["linux"]))))

    def test_required_affinity_in_windows_or_linux_is_not_exclusive(self):
        self.assertFalse(
            is_windows_pod_spec(_required_affinity_terms(_os_in_term(["windows", "linux"])))
        )

    def test_required_affinity_or_terms_windows_and_linux_is_not_windows(self):
        spec = _required_affinity_terms(
            _os_in_term(["windows"]),
            _os_in_term(["linux"]),
        )
        self.assertFalse(is_windows_pod_spec(spec))

    def test_required_affinity_or_terms_windows_and_non_os_is_not_windows(self):
        spec = _required_affinity_terms(
            _os_in_term(["windows"]),
            {
                "matchExpressions": [
                    {"key": "disktype", "operator": "In", "values": ["ssd"]}
                ]
            },
        )
        self.assertFalse(is_windows_pod_spec(spec))

    def test_required_affinity_all_or_terms_require_windows(self):
        spec = _required_affinity_terms(
            _os_in_term(["windows"]),
            _os_in_term(["windows"], key="beta.kubernetes.io/os"),
        )
        self.assertTrue(is_windows_pod_spec(spec))

    def test_required_affinity_not_in_windows_is_not_windows(self):
        self.assertFalse(
            is_windows_pod_spec(
                _required_affinity_terms(_os_in_term(["windows"], operator="NotIn"))
            )
        )

    def test_required_affinity_not_in_linux_is_not_windows(self):
        self.assertFalse(
            is_windows_pod_spec(
                _required_affinity_terms(_os_in_term(["linux"], operator="NotIn"))
            )
        )

    def test_required_affinity_does_not_exist_os_is_not_windows(self):
        term = {
            "matchExpressions": [
                {"key": "kubernetes.io/os", "operator": "DoesNotExist"}
            ]
        }
        self.assertFalse(is_windows_pod_spec(_required_affinity_terms(term)))

    def test_null_node_selector_is_not_windows(self):
        self.assertFalse(is_windows_pod_spec({"nodeSelector": None, "containers": []}))
        self.assertFalse(is_windows_pod_spec({"nodeSelector": {}, "containers": []}))

    def test_preferred_affinity_only_is_not_strong_signal(self):
        spec = {
            "affinity": {
                "nodeAffinity": {
                    "preferredDuringSchedulingIgnoredDuringExecution": [
                        {
                            "weight": 1,
                            "preference": {
                                "matchExpressions": [
                                    {
                                        "key": "kubernetes.io/os",
                                        "operator": "In",
                                        "values": ["windows"],
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        }
        self.assertFalse(is_windows_pod_spec(spec))

    def test_affinity_malformed(self):
        self.assertFalse(is_windows_pod_spec({"affinity": "windows"}))
        self.assertFalse(is_windows_pod_spec({"affinity": {"nodeAffinity": []}}))
        self.assertFalse(
            is_windows_pod_spec(
                {
                    "affinity": {
                        "nodeAffinity": {
                            "requiredDuringSchedulingIgnoredDuringExecution": {
                                "nodeSelectorTerms": "bad"
                            }
                        }
                    }
                }
            )
        )
        self.assertFalse(is_windows_pod_spec(_required_affinity_terms("not-a-term")))
        self.assertFalse(is_windows_pod_spec(_required_affinity_terms({})))

    def test_toleration_only_is_not_strong_signal(self):
        spec = {
            "tolerations": [
                {
                    "key": "os",
                    "operator": "Equal",
                    "value": "windows",
                    "effect": "NoSchedule",
                }
            ]
        }
        self.assertFalse(is_windows_pod_spec(spec))

    def test_runtime_class_only_is_not_strong_signal(self):
        self.assertFalse(is_windows_pod_spec({"runtimeClassName": "windows-2019"}))

    def test_windows_image_only_is_not_strong_signal(self):
        spec = {
            "containers": [
                {"name": "web", "image": "mcr.microsoft.com/windows/servercore:ltsc2019"}
            ]
        }
        self.assertFalse(is_windows_pod_spec(spec))

    def test_combined_os_name_and_node_selector(self):
        spec = {
            "os": {"name": "windows"},
            "nodeSelector": {"kubernetes.io/os": "windows"},
        }
        self.assertTrue(is_windows_pod_spec(spec))

    def test_affinity_among_other_match_expressions(self):
        term = {
            "matchExpressions": [
                {"key": "kubernetes.io/arch", "operator": "In", "values": ["amd64"]},
                {"key": "kubernetes.io/os", "operator": "In", "values": ["windows"]},
            ]
        }
        self.assertTrue(is_windows_pod_spec(_required_affinity_terms(term)))

    def test_deployment_root_spec_without_template_is_not_windows(self):
        deployment_root_spec = {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "win"}},
            "template": {
                "spec": {
                    "nodeSelector": {"kubernetes.io/os": "windows"},
                    "containers": [{"name": "c", "image": "busybox"}],
                }
            },
        }
        self.assertFalse(is_windows_pod_spec(deployment_root_spec))
        self.assertTrue(is_windows_pod_spec(deployment_root_spec["template"]["spec"]))


if __name__ == "__main__":
    unittest.main()
