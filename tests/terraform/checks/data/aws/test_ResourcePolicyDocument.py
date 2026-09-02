import unittest
from pathlib import Path

from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.data.aws.ResourcePolicyDocument import check
from checkov.terraform.runner import Runner


class TestResourcePolicyDocument(unittest.TestCase):
    def test(self):
        test_files_dir = Path(__file__).parent / "example_ResourcePolicyDocument"

        report = Runner().run(root_folder=str(test_files_dir), runner_filter=RunnerFilter(checks=[check.id]))
        summary = report.get_summary()

        passing_resources = {
            "aws_iam_policy_document.pass",
            "aws_iam_policy_document.pass2",
            "aws_iam_policy_document.pass_unrestrictable",
            "aws_iam_policy_document.pass_condition",
            "aws_iam_policy_document.pass_kms_key_policy",
            "aws_iam_policy_document.pass_kms_replica_key_policy",
            "aws_iam_policy_document.pass_kms_key_policy_resource",
            "aws_iam_policy_document.pass_kms_not_principals",
            "aws_iam_policy_document.pass_kms_case_insensitive",
            "aws_iam_policy_document.kms_not_actions",
        }
        failing_resources = {
            "aws_iam_policy_document.fail",
            "aws_iam_policy_document.fail_kms_without_principals",
            "aws_iam_policy_document.fail_non_kms_resource_policy",
            "aws_iam_policy_document.fail_kms_mixed_actions",
            "aws_iam_policy_document.fail_kms_global_wildcard",
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
