import os
import json
import unittest

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.SQSQueuePolicyAnyPrincipal import check
from checkov.terraform.runner import Runner


class TestBackupVaultEncrypted(unittest.TestCase):
    def test(self):
        runner = Runner()
        current_dir = os.path.dirname(os.path.realpath(__file__))

        test_files_dir = current_dir + "/example_SQSQueuePolicyAnyPrincipal"
        report = runner.run(root_folder=test_files_dir, runner_filter=RunnerFilter(checks=[check.id]))
        summary = report.get_summary()

        passing_resources = {
            "aws_sqs_queue_policy.q1",
            "aws_sqs_queue_policy.q6",
            "aws_sqs_queue.aq1",
            "aws_sqs_queue.aq6"
        }
        failing_resources = {
            "aws_sqs_queue_policy.q2",
            "aws_sqs_queue_policy.q4",
            "aws_sqs_queue_policy.q5",
            "aws_sqs_queue.aq2",
            "aws_sqs_queue.aq4",
            "aws_sqs_queue.aq5",
        }

        passed_check_resources = set([c.resource for c in report.passed_checks])
        failed_check_resources = set([c.resource for c in report.failed_checks])

        self.assertEqual(summary["passed"], 4)
        self.assertEqual(summary["failed"], 6)
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["parsing_errors"], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)

        # Preserve every original fixture's coverage, including invalid partial
        # wildcard Principal ARNs and unparsed Terraform policy expressions.
        unknown_resources = {
            "aws_sqs_queue_policy.q3", "aws_sqs_queue.aq3",
            "aws_sqs_queue_policy.q7", "aws_sqs_queue.aq7", "aws_sqs_queue_policy.aq8",
        }
        unknown_results = {}
        for definition in runner.definitions.values():
            for resource in definition.get("resource", []):
                for kind in ("aws_sqs_queue", "aws_sqs_queue_policy"):
                    for name, conf in resource.get(kind, {}).items():
                        address = f"{kind}.{name}"
                        if address in unknown_resources:
                            unknown_results[address] = check.scan_resource_conf(conf)
        self.assertEqual({name: CheckResult.UNKNOWN for name in unknown_resources}, unknown_results)

    def test_policy_forms_and_public_grants(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": "*"}
        private = {**public, "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"}}
        for name, document, expected in (
            ("public", {"Statement": [public]}, CheckResult.FAILED),
            ("public second", {"Statement": [private, public]}, CheckResult.FAILED),
            ("single statement", {"Statement": public}, CheckResult.FAILED),
            ("AWS wildcard", {"Statement": [{**public, "Principal": {"AWS": "*"}}]}, CheckResult.FAILED),
            ("AWS list", {"Statement": [{**public, "Principal": {"AWS": ["123456789012", "*"]}}]}, CheckResult.FAILED),
            ("all SQS actions", {"Statement": [{**public, "Action": "sqs:*"}]}, CheckResult.FAILED),
            ("receive wildcard", {"Statement": [{**public, "Action": "SQS:Receive*"}]}, CheckResult.FAILED),
            ("metadata action", {"Statement": [{**public, "Action": "sqs:GetQueueAttributes"}]}, CheckResult.FAILED),
            ("purge action", {"Statement": [{**public, "Action": "sqs:PurgeQueue"}]}, CheckResult.FAILED),
            ("private", {"Statement": [private]}, CheckResult.PASSED),
            ("service", {"Statement": [{**public, "Principal": {"Service": "sns.amazonaws.com"}}]}, CheckResult.PASSED),
            ("deny only", {"Statement": [{**public, "Effect": "Deny"}]}, CheckResult.PASSED),
            ("malformed pasted fields", {"Statement": [{**public, "Principal": "", "Action": "sqs:"}]}, CheckResult.UNKNOWN),
            ("missing principal", {"Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": "*"}]}, CheckResult.UNKNOWN),
            ("partial wildcard principal", {"Statement": [{**public, "Principal": {"AWS": "arn:aws:iam::*:role/app"}}]}, CheckResult.UNKNOWN),
            ("service wildcard", {"Statement": [{**public, "Principal": {"Service": "*"}}]}, CheckResult.UNKNOWN),
            ("owner-only administrative action", {"Statement": [{**public, "Action": "sqs:SetQueueAttributes"}]}, CheckResult.UNKNOWN),
            ("API batch name is not IAM action", {"Statement": [{**public, "Action": "sqs:SendMessageBatch"}]}, CheckResult.UNKNOWN),
            ("other service scope", {"Statement": [{**public, "Resource": "arn:aws:s3:::bucket/*"}]}, CheckResult.UNKNOWN),
            ("malformed statement", {"Statement": ["invalid"]}, CheckResult.UNKNOWN),
            ("missing statements", {}, CheckResult.UNKNOWN),
        ):
            for policy in (document, json.dumps(document)):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"policy": [policy]}), expected)

    def test_conditions_and_denies_are_unknown(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "sqs:*", "Resource": "*"}
        for condition in (
            {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}},
            {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:eu-west-1:123456789012:topic"}},
            {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}},
            {"ForAllValues:StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}},
            {"StringEquals": "malformed"},
        ):
            with self.subTest(condition=condition):
                self.assertEqual(check.scan_resource_conf({"policy": [{"Statement": [
                    {**public, "Condition": condition}]}]}), CheckResult.UNKNOWN)
        for statements in (
            [public, {**public, "Effect": "Deny", "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-example"}}}],
            [{**public, "Effect": "Deny"}, public],
        ):
            with self.subTest(statements=statements):
                self.assertEqual(check.scan_resource_conf({"policy": [{"Statement": statements}]}), CheckResult.UNKNOWN)

    def test_not_action_complements(self):
        grant = {"Effect": "Allow", "Principal": "*", "NotAction": "s3:*", "Resource": "*"}
        for name, statement, expected in (
            ("other service excluded", grant, CheckResult.FAILED),
            ("some SQS actions excluded", {**grant, "NotAction": ["sqs:ReceiveMessage", "sqs:DeleteMessage"]}, CheckResult.FAILED),
            ("all SQS excluded", {**grant, "NotAction": "sqs:*"}, CheckResult.PASSED),
            ("all SQS excluded with unknown resource", {**grant, "NotAction": "sqs:*", "Resource": "${var.resource}"}, CheckResult.PASSED),
            ("all actions excluded", {**grant, "NotAction": "*"}, CheckResult.PASSED),
            ("fixed queue scope", {**grant, "Resource": "arn:aws:sqs:eu-west-1:123456789012:queue"}, CheckResult.FAILED),
            ("unknown scope", {**grant, "Resource": "${aws_sqs_queue.app.arn}"}, CheckResult.UNKNOWN),
            ("other scope", {**grant, "Resource": "arn:aws:s3:::bucket/*"}, CheckResult.UNKNOWN),
            ("both action elements", {**grant, "Action": "sqs:*"}, CheckResult.UNKNOWN),
            ("unknown exclusions", {**grant, "NotAction": "${var.actions}"}, CheckResult.UNKNOWN),
            ("NotResource", {**grant, "NotResource": "*"}, CheckResult.UNKNOWN),
        ):
            for policy in ({"Statement": [statement]}, json.dumps({"Statement": [statement]})):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"policy": [policy]}), expected)

    def test_missing_and_unresolved_policy(self):
        for conf in ({}, {"policy": []}, {"policy": [""]}):
            with self.subTest(conf=conf):
                self.assertEqual(check.scan_resource_conf(conf), CheckResult.PASSED)
        for value in ("not JSON", "data.aws_iam_policy_document.queue.json", "${jsonencode(var.policy)}"):
            with self.subTest(value=value):
                self.assertEqual(check.scan_resource_conf({"policy": [value]}), CheckResult.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
