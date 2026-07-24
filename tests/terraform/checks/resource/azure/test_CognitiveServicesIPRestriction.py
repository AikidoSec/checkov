import os
import unittest

from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.azure.CognitiveServicesIPRestriction import check
from checkov.terraform.runner import Runner


class TestCognitiveServicesIPRestriction(unittest.TestCase):

    def test(self):
        runner = Runner()
        current_dir = os.path.dirname(os.path.realpath(__file__))

        test_files_dir = os.path.join(current_dir, "example_CognitiveServicesIPRestriction")
        report = runner.run(root_folder=test_files_dir, runner_filter=RunnerFilter(checks=[check.id]))
        summary = report.get_summary()

        passing_resources = {
            "azurerm_cognitive_account.pass_private",
            "azurerm_cognitive_account.pass_private_with_acls",
            "azurerm_cognitive_account.pass_missing_acls",
            "azurerm_cognitive_account.pass_allow_action",
            "azurerm_cognitive_account.pass_literal_ips",
            "azurerm_cognitive_account.pass_lowercase_deny",
            "azurerm_cognitive_account.pass_var_ips",
            "azurerm_cognitive_account.pass_dynamic_concat",
        }
        failing_resources = {
            "azurerm_cognitive_account.fail_missing_ips",
            "azurerm_cognitive_account.fail_empty_ips",
            "azurerm_cognitive_account.fail_lowercase_deny_empty_ips",
            "azurerm_cognitive_account.fail_empty_string_ips",
            "azurerm_cognitive_account.fail_open_cidr",
            "azurerm_cognitive_account.fail_open_cidr_among_valid_ips",
            "azurerm_cognitive_account.fail_open_ipv6",
            "azurerm_cognitive_account.fail_open_star",
            "azurerm_cognitive_account.fail_empty_var_ips",
            "azurerm_cognitive_account.fail_public_var_ips",
            "azurerm_cognitive_account.fail_dynamic_concat_public",
        }

        passed_check_resources = {c.resource for c in report.passed_checks}
        failed_check_resources = {c.resource for c in report.failed_checks}

        self.assertEqual(summary["passed"], len(passing_resources))
        self.assertEqual(summary["failed"], len(failing_resources))
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["parsing_errors"], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)


if __name__ == "__main__":
    unittest.main()
