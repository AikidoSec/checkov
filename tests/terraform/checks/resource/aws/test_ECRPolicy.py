import json
import unittest
from pathlib import Path

from checkov.runner_filter import RunnerFilter
from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.aws.ECRPolicy import check
from checkov.terraform.runner import Runner


class TestECRPolicy(unittest.TestCase):
    def test(self):
        # given
        test_files_dir = Path(__file__).parent / "example_ECRPolicy"

        # when
        runner = Runner()
        report = runner.run(root_folder=str(test_files_dir), runner_filter=RunnerFilter(checks=[check.id]))

        # then
        summary = report.get_summary()

        passing_resources = {
            "aws_ecr_repository_policy.pass",
            "aws_ecr_repository_policy.empty",
        }
        failing_resources = {
            "aws_ecr_repository_policy.fail",
        }
        # Keep every original fixture asserted. Conditions are intentionally out
        # of scope for this narrow patch; missing principals are malformed input.
        unknown_resources = {
            "aws_ecr_repository_policy.pass_conditional",
            "aws_ecr_repository_policy.cond_any_pass",
            "aws_ecr_repository_policy.cond_equals_pass",
            "aws_ecr_repository_policy.pass_without_principal",
            "aws_ecr_repository_policy.fail_conditional",
        }

        passed_check_resources = {c.resource for c in report.passed_checks}
        failed_check_resources = {c.resource for c in report.failed_checks}

        self.assertEqual(summary["passed"], len(passing_resources))
        self.assertEqual(summary["failed"], len(failing_resources))
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["parsing_errors"], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)

        # Runner reports omit UNKNOWN results, so assert them on the same rendered
        # configurations rather than merely checking their absence from findings.
        unknown_results = {}
        for definition in runner.definitions.values():
            for resource in definition.get("resource", []):
                for name, conf in resource.get("aws_ecr_repository_policy", {}).items():
                    address = f"aws_ecr_repository_policy.{name}"
                    if address in unknown_resources:
                        unknown_results[address] = check.scan_resource_conf(conf)
        self.assertEqual({address: CheckResult.UNKNOWN for address in unknown_resources}, unknown_results)

    def test_policy_forms(self):
        private = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                   "Action": "ecr:BatchGetImage"}
        public = {"Effect": "Allow", "Principal": "*", "Action": "ecr:BatchGetImage"}
        for name, document, expected in (
            ("private", {"Statement": [private]}, CheckResult.PASSED),
            ("public", {"Statement": [public]}, CheckResult.FAILED),
            ("public second", {"Statement": [private, public]}, CheckResult.FAILED),
            ("conditional first", {"Statement": [{**public, "Condition": {
                "StringEquals": {"aws:PrincipalOrgID": "o-example"}}}, public]}, CheckResult.FAILED),
            ("single statement", {"Statement": public}, CheckResult.FAILED),
            ("AWS wildcard", {"Statement": [{**public, "Principal": {"AWS": "*"}}]}, CheckResult.FAILED),
            ("AWS list", {"Statement": [{**public, "Principal": {"AWS": ["123456789012", "*"]}}]}, CheckResult.FAILED),
            ("deny only", {"Statement": [{**public, "Effect": "Deny"}]}, CheckResult.PASSED),
            ("missing principal", {"Statement": [{"Effect": "Allow", "Action": "ecr:*"}]}, CheckResult.UNKNOWN),
            ("missing effect", {"Statement": [{"Principal": "*", "Action": "ecr:*"}]}, CheckResult.UNKNOWN),
            ("missing action", {"Statement": [{"Effect": "Allow", "Principal": "*"}]}, CheckResult.UNKNOWN),
            ("invalid statement", {"Statement": ["invalid"]}, CheckResult.UNKNOWN),
            ("missing statements", {}, CheckResult.UNKNOWN),
            ("unresolved principal", {"Statement": [{**public, "Principal": "${var.principal}"}]}, CheckResult.UNKNOWN),
            ("invalid ARN wildcard", {"Statement": [{**public, "Principal": {"AWS": "arn:aws:iam::*:root"}}]}, CheckResult.UNKNOWN),
            ("invalid service wildcard", {"Statement": [{**public, "Principal": {"Service": "*"}}]}, CheckResult.UNKNOWN),
            ("null condition", {"Statement": [{**public, "Condition": None}]}, CheckResult.UNKNOWN),
            ("case insensitive action", {"Statement": [{**public, "Action": "ECR:BatchGetImage"}]}, CheckResult.FAILED),
        ):
            for policy in (document, json.dumps(document)):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"policy": [policy]}), expected)

    def test_conditions_and_denies_are_not_assumed_public(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "ecr:BatchGetImage", "Resource": "*"}
        documents = [
            {"Statement": [{**public, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}]},
            {"Statement": [{**public, "Condition": {"StringLike": {"aws:PrincipalOrgID": ["o-example", "*"]}}}]},
            {"Statement": [{**public, "Condition": {"ForAllValues:StringEquals": {"aws:PrincipalOrgID": "o-example"}}}]},
            {"Statement": [public, {**public, "Effect": "Deny", "Condition": {
                "StringNotEquals": {"aws:SourceVpce": "vpce-example"}}}]},
            {"Statement": [{**public, "Condition": {"StringEquals": "malformed"}}]},
            {"Statement": [{**public, "NotPrincipal": {"AWS": "123456789012"}}]},
        ]
        for document in documents:
            with self.subTest(document=document):
                self.assertEqual(check.scan_resource_conf({"policy": [document]}), CheckResult.UNKNOWN)

    def test_missing_and_unresolved_policies(self):
        for conf in ({}, {"policy": []}, {"policy": [""]}):
            with self.subTest(conf=conf):
                self.assertEqual(check.scan_resource_conf(conf), CheckResult.PASSED)
        for policy in ("not JSON", "${data.aws_iam_policy_document.repository.json}", "${jsonencode(var.policy)}"):
            with self.subTest(policy=policy):
                self.assertEqual(check.scan_resource_conf({"policy": [policy]}), CheckResult.UNKNOWN)

if __name__ == "__main__":
    unittest.main()
