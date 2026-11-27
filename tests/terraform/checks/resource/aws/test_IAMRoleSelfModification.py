import json
import tempfile
import unittest
from pathlib import Path

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.IAMPrivilegeEscalation import check
from checkov.terraform.checks.utils.base_cloudsplaining_iam_scanner import BaseTerraformCloudsplainingIAMScanner
from checkov.terraform.runner import Runner


def allow(actions, resource="*", **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}


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
