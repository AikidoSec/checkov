import os
import json
import tempfile
import unittest
from pathlib import Path

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.SNSTopicPolicyAnyPrincipal import check
from checkov.terraform.runner import Runner


class TestBackupVaultEncrypted(unittest.TestCase):
    def test(self):
        runner = Runner()
        current_dir = os.path.dirname(os.path.realpath(__file__))

        test_files_dir = current_dir + "/example_SNSTopicPolicyAnyPrincipal"
        report = runner.run(root_folder=test_files_dir, runner_filter=RunnerFilter(checks=[check.id]))
        summary = report.get_summary()

        passing_resources = {
            "aws_sns_topic_policy.sns_tp1",
            "aws_sns_topic_policy.sns_tp6",
        }
        failing_resources = {
            "aws_sns_topic_policy.sns_tp2",
            "aws_sns_topic_policy.sns_tp4",
            "aws_sns_topic_policy.sns_tp5",
        }

        passed_check_resources = set([c.resource for c in report.passed_checks])
        failed_check_resources = set([c.resource for c in report.failed_checks])

        self.assertEqual(summary["passed"], 2)
        self.assertEqual(summary["failed"], 3)
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["parsing_errors"], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)

        unknown_resources = {"sns_tp3", "sns_tp_unknown"}
        unknown_results = {}
        for definition in runner.definitions.values():
            for resource in definition.get("resource", []):
                for name, conf in resource.get("aws_sns_topic_policy", {}).items():
                    if name in unknown_resources:
                        unknown_results[name] = check.scan_resource_conf(conf)
        self.assertEqual({name: CheckResult.UNKNOWN for name in unknown_resources}, unknown_results)

    def test_policy_forms_and_messaging_grants(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Resource": "*"}
        private = {**public, "Principal": {"AWS": "123456789012"}}
        for name, statements, expected in (
            ("publish", [public], CheckResult.FAILED),
            ("subscribe", [{**public, "Action": "sns:Subscribe"}], CheckResult.FAILED),
            ("all SNS actions", [{**public, "Action": "sns:*"}], CheckResult.FAILED),
            ("action wildcard", [{**public, "Action": "SNS:Sub*"}], CheckResult.FAILED),
            ("public second", [private, public], CheckResult.FAILED),
            ("AWS wildcard", [{**public, "Principal": {"AWS": "*"}}], CheckResult.FAILED),
            ("AWS list", [{**public, "Principal": {"AWS": ["123456789012", "*"]}}], CheckResult.FAILED),
            ("private", [private], CheckResult.PASSED),
            ("service", [{**public, "Principal": {"Service": "s3.amazonaws.com"}}], CheckResult.PASSED),
            ("deny only", [{**public, "Effect": "Deny"}], CheckResult.PASSED),
            ("metadata only", [{**public, "Action": "sns:GetTopicAttributes"}], CheckResult.UNKNOWN),
            ("legacy Receive-only entry", [{**public, "Action": "sns:Receive"}], CheckResult.UNKNOWN),
            ("administration only", [{**public, "Action": "sns:SetTopicAttributes"}], CheckResult.UNKNOWN),
            ("API batch name", [{**public, "Action": "sns:PublishBatch"}], CheckResult.UNKNOWN),
            ("partial wildcard principal", [{**public, "Principal": {"AWS": "arn:aws:iam::*:role/app"}}], CheckResult.UNKNOWN),
            ("service wildcard", [{**public, "Principal": {"Service": "*"}}], CheckResult.UNKNOWN),
            ("unresolved principal", [{**public, "Principal": "${var.principal}"}], CheckResult.UNKNOWN),
            ("missing action", [{"Effect": "Allow", "Principal": "*", "Resource": "*"}], CheckResult.UNKNOWN),
            ("malformed statement", ["invalid"], CheckResult.UNKNOWN),
        ):
            for policy in ({"Statement": statements}, json.dumps({"Statement": statements})):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"policy": [policy]}), expected)
        self.assertEqual(check.scan_resource_conf({"policy": [{"Statement": public}]}), CheckResult.FAILED)

    def test_conditions_and_denies_are_unknown(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Resource": "*"}
        for condition in (
            {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}},
            {"StringEquals": {"aws:SourceOwner": "123456789012"}},
            {"ArnEquals": {"aws:SourceArn": "arn:aws:s3:::example-bucket"}},
            {"StringEquals": {"sns:Protocol": "https"}},
            {"StringEquals": "malformed"},
            None,
        ):
            with self.subTest(condition=condition):
                policy = {"Statement": [{**public, "Condition": condition}]}
                self.assertEqual(check.scan_resource_conf({"policy": [policy]}), CheckResult.UNKNOWN)
        restricted_deny = {**public, "Effect": "Deny", "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-example"}}}
        for statements in ([public, restricted_deny], [restricted_deny, public]):
            with self.subTest(statements=statements):
                self.assertEqual(check.scan_resource_conf({"policy": [{"Statement": statements}]}), CheckResult.UNKNOWN)

    def test_not_action_and_resource_alternatives(self):
        topic = "arn:aws:sns:eu-west-1:123456789012:topic"
        bucket = "arn:aws:s3:::example-bucket/*"
        base = {"Effect": "Allow", "Principal": "*", "Resource": "*", "NotAction": "s3:*"}
        for name, statement, expected in (
            ("other service excluded", base, CheckResult.FAILED),
            ("publish excluded", {**base, "NotAction": "sns:Publish"}, CheckResult.FAILED),
            ("all SNS excluded", {**base, "NotAction": "sns:*"}, CheckResult.PASSED),
            ("all actions excluded", {**base, "NotAction": "*"}, CheckResult.PASSED),
            ("both action elements", {**base, "Action": "sns:*"}, CheckResult.UNKNOWN),
            ("unknown exclusions", {**base, "NotAction": "${var.actions}"}, CheckResult.UNKNOWN),
            ("unknown scope", {**base, "Resource": "${var.arn}"}, CheckResult.UNKNOWN),
            ("single resource list", {**base, "Resource": [topic]}, CheckResult.FAILED),
            ("unknown then known topic", {**base, "Resource": ["${var.arn}", topic]}, CheckResult.UNKNOWN),
            ("topic then other service", {**base, "Resource": [topic, bucket]}, CheckResult.UNKNOWN),
            ("other service then topic", {**base, "Resource": [bucket, topic]}, CheckResult.UNKNOWN),
            ("other service only", {**base, "Resource": bucket}, CheckResult.UNKNOWN),
            ("malformed resource", {**base, "Resource": [topic, "arn:invalid"]}, CheckResult.UNKNOWN),
            ("messaging excluded", {**base, "NotAction": ["sns:Publish", "sns:Subscribe"]}, CheckResult.UNKNOWN),
        ):
            for policy in ({"Statement": [statement]}, json.dumps({"Statement": [statement]})):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"policy": [policy]}), expected)
        for resources in ([topic, bucket], [bucket, topic]):
            statement = {"Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Resource": resources}
            # SNS documents a one-resource quota, unlike generic IAM Resource lists.
            self.assertEqual(check.scan_resource_conf({"policy": [{"Statement": [statement]}]}), CheckResult.UNKNOWN)

    def test_runner_includes_inline_topic_policy(self):
        text = '''resource "aws_sns_topic" "public" {
  name = "scanner-example"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "sns:Subscribe", Resource = "*" }]
  })
}
resource "aws_sns_topic" "without_policy" { name = "scanner-example-private" }
resource "aws_sns_topic" "disabled" {
  count = 0
  name = "scanner-example-disabled"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "sns:Publish", Resource = "*" }]
  })
}'''
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "main.tf").write_text(text)
            report = Runner().run(root_folder=folder, runner_filter=RunnerFilter(checks=[check.id]))
            self.assertEqual(report.parsing_errors, [])
            self.assertEqual({r.resource for r in report.failed_checks}, {"aws_sns_topic.public"})
            self.assertEqual({r.resource for r in report.passed_checks}, {"aws_sns_topic.without_policy"})

    def test_missing_and_unparsed_policies(self):
        for conf in ({}, {"policy": []}, {"policy": [""]}):
            self.assertEqual(check.scan_resource_conf(conf), CheckResult.PASSED)
        for value in ("not JSON", "data.aws_iam_policy_document.topic.json", "${jsonencode(var.policy)}"):
            with self.subTest(value=value):
                self.assertEqual(check.scan_resource_conf({"policy": [value]}), CheckResult.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
