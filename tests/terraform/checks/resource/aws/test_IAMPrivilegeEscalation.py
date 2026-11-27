import unittest
import json
import tempfile
from pathlib import Path

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.IAMPrivilegeEscalation import check
from checkov.terraform.checks.utils.base_cloudsplaining_iam_scanner import BaseTerraformCloudsplainingIAMScanner
from checkov.terraform.runner import Runner


class TestIAMPolicyAttachedToGroupOrRoles(unittest.TestCase):
    def setUp(self):
        # The shared cache is keyed by entity paths. Keep independent fixture
        # scans from reusing another test's policy with the same path/name.
        BaseTerraformCloudsplainingIAMScanner.policy_document_cache.clear()

    def tearDown(self):
        BaseTerraformCloudsplainingIAMScanner.policy_document_cache.clear()

    def test(self):
        # given
        test_files_dir = Path(__file__).parent / "example_IAMPrivilegeEscalation"

        # when
        report = Runner().run(root_folder=str(test_files_dir), runner_filter=RunnerFilter(checks=[check.id]))

        # then
        summary = report.get_summary()

        passing_resources = {
            "aws_iam_policy.passing",
        }
        failing_resources = {
            'aws_iam_policy.privilege_escalation'
        }

        passed_check_resources = {c.resource for c in report.passed_checks}
        failed_check_resources = {c.resource for c in report.failed_checks}

        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["parsing_errors"], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)

    def test_escalation_combinations_and_known_limits(self):
        def allow(actions, resource="*", **extra):
            return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}

        lambda_path = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
        for name, statements, expected in (
            ("passrole_lambda", [allow(lambda_path)], CheckResult.FAILED),
            ("policy_version", [allow(["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"])], CheckResult.FAILED),
            ("create_version_sets_default", [allow("iam:CreatePolicyVersion")], CheckResult.FAILED),
            ("mint_credentials", [allow(["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:PutUserPolicy"])], CheckResult.FAILED),
            ("passrole_ec2", [allow(["iam:PassRole", "ec2:RunInstances"])], CheckResult.FAILED),
            ("same_document_statements", [allow("iam:PassRole"), allow(["lambda:CreateFunction", "lambda:InvokeFunction"])], CheckResult.FAILED),
            ("passrole_alone", [allow("iam:PassRole")], CheckResult.PASSED),
            ("lambda_create_only", [allow(["iam:PassRole", "lambda:CreateFunction"])], CheckResult.PASSED),
            ("read_only", [allow("s3:GetObject")], CheckResult.PASSED),
            ("scoped_passrole", [allow("iam:PassRole", "arn:aws:iam::123456789012:role/app"), allow("ec2:RunInstances")], CheckResult.PASSED),
            ("scoped_policy_version", [allow("iam:CreatePolicyVersion", "arn:aws:iam::123456789012:policy/app")], CheckResult.PASSED),
            ("explicit_deny", [allow(lambda_path), {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}], CheckResult.PASSED),
            ("condition_suppresses_analysis", [allow(lambda_path, Condition={"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}})], CheckResult.PASSED),
            # Managed-policy attachment relationships and time-constrained
            # escalation paths remain limitations; these PASS results are not
            # proof of safety. Bound inline-role self-writes are tested below.
            ("managed_role_writes_not_linked", [allow(["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"])], CheckResult.PASSED),
            ("unrelated_condition_missed", [allow(lambda_path, Condition={"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}})], CheckResult.PASSED),
        ):
            with self.subTest(name=name):
                conf = {"policy": [{"Version": "2012-10-17", "Statement": statements}]}
                result = check.run("/combination.tf", conf, name, "aws_iam_policy", None)
                self.assertEqual(result["result"], expected)

    def test_separate_policies_are_not_combined(self):
        for name, actions in (("passrole", ["iam:PassRole"]), ("compute", ["ec2:RunInstances"])):
            with self.subTest(name=name):
                conf = {"role": ["scanner-example-role"], "policy": [{"Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}]}
                self.assertEqual(check.run("/split.tf", conf, name, "aws_iam_role_policy", None)["result"], CheckResult.PASSED)

    def test_runner_handles_policy_resources_and_inline_policies(self):
        policies = {
            "managed_lambda": ("aws_iam_policy", ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]),
            "managed_version": ("aws_iam_policy", ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]),
            "inline_user": ("aws_iam_user_policy", ["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:PutUserPolicy"]),
            "inline_role_self_edit": ("aws_iam_role_policy", ["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"]),
            "scoped": ("aws_iam_policy", ["iam:CreatePolicyVersion"]),
            "disabled": ("aws_iam_policy", ["iam:CreatePolicyVersion"]),
        }
        blocks = []
        bindings = {
            "aws_iam_role_policy": 'role = "scanner-example-role"',
            "aws_iam_user_policy": 'user = "scanner-example-user"',
        }
        for name, (kind, actions) in policies.items():
            resource = "arn:aws:iam::123456789012:policy/app" if name == "scoped" else "*"
            policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}]})
            count = "count = 0" if name == "disabled" else ""
            blocks.append(f'''resource "{kind}" "{name}" {{
  name = "scanner-example-{name}"
  {bindings.get(kind, "")}
  {count}
  policy = <<POLICY
{policy}
POLICY
}}''')
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "main.tf").write_text("\n".join(blocks))
            report = Runner().run(root_folder=folder, runner_filter=RunnerFilter(checks=[check.id]))
            self.assertEqual(report.parsing_errors, [])
            self.assertEqual({r.resource for r in report.failed_checks}, {
                "aws_iam_policy.managed_lambda", "aws_iam_policy.managed_version", "aws_iam_user_policy.inline_user",
                "aws_iam_role_policy.inline_role_self_edit"})
            self.assertEqual({r.resource for r in report.passed_checks}, {
                "aws_iam_policy.scoped"})


if __name__ == "__main__":
    unittest.main()
