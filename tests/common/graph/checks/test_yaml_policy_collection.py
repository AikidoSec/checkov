from importlib import import_module
import unittest

import pytest

from tests.common.graph.checks.test_yaml_policies_base import TestYamlPoliciesBase


@pytest.mark.parametrize("module_name", [
    "tests.ansible.checks.graph_checks.test_yaml_policies",
    "tests.arm.graph_builder.checks.test_yaml_policies",
    "tests.bicep.graph.checks.test_yaml_policies",
    "tests.cloudformation.graph.checks.test_yaml_policies",
    "tests.dockerfile.graph_builder.checks.test_yaml_policies",
    "tests.github_actions.checks.graph_checks.test_yaml_policies",
    "tests.kubernetes.graph.checks.test_yaml_policies",
])
def test_only_parameterized_graph_policy_classes_are_collectable(module_name: str) -> None:
    module = import_module(module_name)
    assert TestYamlPoliciesBase.__test__ is False
    assert module.TestYamlPolicies.__test__ is False

    backends = set()
    for name, cls in vars(module).items():
        if name.startswith("TestYamlPolicies_") and isinstance(cls, type):
            assert cls.__test__ is True
            assert unittest.TestLoader().getTestCaseNames(cls)
            backends.add(cls.graph_framework)
    assert backends == {"NETWORKX", "IGRAPH"}
