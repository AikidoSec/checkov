import unittest
import json
import tempfile
from pathlib import Path

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.IAMPrivilegeEscalation import check
from checkov.terraform.checks.utils.base_cloudsplaining_iam_scanner import BaseTerraformCloudsplainingIAMScanner
from checkov.terraform.runner import Runner


def allow(actions, resource="*", **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}


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


class TestIAMRoleSelfModification(unittest.TestCase):
    def setUp(self):
        BaseTerraformCloudsplainingIAMScanner.policy_document_cache.clear()

    def tearDown(self):
        BaseTerraformCloudsplainingIAMScanner.policy_document_cache.clear()

    def cases(self):
        failed, passed, unknown = CheckResult.FAILED, CheckResult.PASSED, CheckResult.UNKNOWN
        other_role = "arn:aws:iam::123456789012:role/other-example"
        self_role = "arn:aws:iam::123456789012:role/scanner-example"
        write = allow("iam:PutRolePolicy")
        deny = {**write, "Effect": "Deny"}
        return [
            ("role_modification_combination", [allow(["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"])], failed),
            ("put_inline_policy", [write], failed),
            ("attach_managed_policy", [allow("iam:AttachRolePolicy")], failed),
            ("action_list", [allow(["iam:GetRole", "iam:PutRolePolicy"])], failed),
            ("case_insensitive_action", [allow("iam:putrolepolicy")], failed),
            ("action_prefix", [allow("iam:PutRole*")], failed),
            ("mixed_resources", [allow("iam:PutRolePolicy", [other_role, "*"])], failed),
            ("empty_condition", [allow("iam:PutRolePolicy", Condition={})], failed),
            ("unrelated_condition", [allow("iam:GetRole", Condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}}), write], failed),
            ("conditioned_allow_does_not_mask", [allow("iam:PutRolePolicy", Condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}}), write], failed),
            ("unrelated_deny", [write, {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}], failed),
            ("one_write_still_allowed", [allow(["iam:PutRolePolicy", "iam:AttachRolePolicy"]), deny], failed),
            ("trust_modification_only", [allow("iam:UpdateAssumeRolePolicy")], passed),
            ("passrole_only", [allow("iam:PassRole")], passed),
            ("read_only", [allow(["iam:GetRole", "iam:ListRolePolicies"])], passed),
            ("scoped_other_role", [allow("iam:PutRolePolicy", other_role)], passed),
            # Resource-scoped self-writes remain a library limitation, not proof
            # of safety. This patch does not add role/ARN graph matching.
            ("scoped_self_role_not_analyzed", [allow("iam:PutRolePolicy", self_role)], passed),
            ("resource_exclusion_not_analyzed", [{"Effect": "Allow", "Action": "iam:PutRolePolicy", "NotResource": self_role}], passed),
            ("conflicting_resource_fields", [allow("iam:PutRolePolicy", NotResource=self_role)], unknown),
            ("explicit_deny", [write, deny], unknown),
            ("attachment_explicit_deny", [allow("iam:AttachRolePolicy"), {"Effect": "Deny", "Action": "iam:AttachRolePolicy", "Resource": "*"}], unknown),
            ("both_writes_denied", [allow(["iam:PutRolePolicy", "iam:AttachRolePolicy"]), {"Effect": "Deny", "Action": ["iam:PutRolePolicy", "iam:AttachRolePolicy"], "Resource": "*"}], unknown),
            ("deny_before_allow", [deny, write], unknown),
            ("scoped_deny", [write, {**deny, "Resource": other_role}], unknown),
            ("conditional_deny", [write, {**deny, "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}}], unknown),
            ("attachment_condition", [allow("iam:AttachRolePolicy", Condition={"ArnEquals": {"iam:PolicyARN": "arn:aws:iam::aws:policy/ReadOnlyAccess"}})], unknown),
            ("inline_policy_condition", [allow("iam:PutRolePolicy", Condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}})], unknown),
            ("deny_only", [deny], passed),
            ("empty_statements", [], passed),
        ]

    def run_policy(self, name, statements, kind="aws_iam_role_policy", **extra):
        conf = {"policy": [{"Version": "2012-10-17", "Statement": statements}], **extra}
        if kind == "aws_iam_role_policy" and "role" not in conf:
            conf["role"] = ["scanner-example"]
        return check.run("/self-modification.tf", conf, name, kind, None)

    def test_inline_role_policy(self):
        for name, statements, expected in self.cases():
            with self.subTest(name=name):
                result = self.run_policy(name, statements)
                self.assertEqual(result["result"], expected)
                if expected == CheckResult.FAILED:
                    self.assertEqual(result["evaluated_keys"], ["policy"])

    def test_generic_permissions_management_does_not_become_self_modification(self):
        statements = [allow(["iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"])]
        for kind in ("aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            with self.subTest(kind=kind):
                self.assertEqual(self.run_policy(kind, statements, kind)["result"], CheckResult.PASSED)

    def test_role_binding_and_unsupported_inputs(self):
        for name, conf, expected in (
            ("no_policy", {"role": ["scanner-example"]}, CheckResult.PASSED),
            # No attached-role evidence: retain existing policy analysis only.
            ("no_role_binding", {"policy": [{"Statement": [allow("iam:PutRolePolicy")]}]}, CheckResult.PASSED),
            ("invalid_role_binding", {"role": [None], "policy": [{"Statement": [allow("iam:PutRolePolicy")]}]}, CheckResult.UNKNOWN),
            ("unresolved_document", {"role": ["scanner-example"], "policy": ["${data.aws_iam_policy_document.example.json}"]}, CheckResult.UNKNOWN),
            ("invalid_policy", {"role": ["scanner-example"], "policy": ["{invalid"]}, CheckResult.UNKNOWN),
        ):
            with self.subTest(name=name):
                self.assertEqual(check.run("/unsupported.tf", conf, name, "aws_iam_role_policy", None)["result"], expected)
        self.assertEqual(self.run_policy("unresolved_role", [allow("iam:PutRolePolicy")], role=["${var.role_name}"])["result"], CheckResult.FAILED)

    def test_existing_escalation_detection_is_unchanged(self):
        actions = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
        for kind in ("aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy"):
            with self.subTest(kind=kind):
                self.assertEqual(self.run_policy(f"existing-{kind}", [allow(actions)], kind)["result"], CheckResult.FAILED)

    def test_runner_jsonencode_and_heredoc(self):
        names = {"role_modification_combination", "put_inline_policy", "trust_modification_only", "scoped_other_role", "attachment_condition", "explicit_deny"}
        cases = [case for case in self.cases() if case[0] in names]
        with tempfile.TemporaryDirectory() as folder:
            blocks = ['''resource "aws_iam_role" "example" {
  name = "scanner-example"
  assume_role_policy = jsonencode({
    Statement = [{Effect = "Allow", Action = "sts:AssumeRole", Principal = {Service = "lambda.amazonaws.com"}}]
  })
}''']
            failed, passed = set(), set()
            for name, statements, result in cases:
                document = json.dumps({"Version": "2012-10-17", "Statement": statements})
                for representation, expression in (("jsonencode", f"jsonencode({document})"), ("heredoc", f"<<POLICY\n{document}\nPOLICY")):
                    address = f"aws_iam_role_policy.{name}_{representation}"
                    blocks.append(f'''resource "aws_iam_role_policy" "{name}_{representation}" {{
  role = aws_iam_role.example.name
  policy = {expression}
}}''')
                    if result == CheckResult.FAILED:
                        failed.add(address)
                    elif result == CheckResult.PASSED:
                        passed.add(address)
            blocks.append('''resource "aws_iam_role_policy" "disabled" {
  count = 0
  role = aws_iam_role.example.name
  policy = jsonencode({Statement = [{Effect = "Allow", Action = "iam:PutRolePolicy", Resource = "*"}]})
}''')
            Path(folder, "main.tf").write_text("\n".join(blocks))
            runner = Runner()
            report = runner.run(root_folder=folder, runner_filter=RunnerFilter(checks=[check.id]))
            self.assertEqual(report.parsing_errors, [])
            self.assertEqual({r.resource for r in report.failed_checks}, failed)
            self.assertEqual({r.resource for r in report.passed_checks}, passed)
            self.assertEqual(report.skipped_checks, [])


if __name__ == "__main__":
    unittest.main()
