import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloudsplaining.scan.resource_policy_document import ResourcePolicyDocument

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.SecretManagerSecretPolicyAnyPrincipal import check
from checkov.terraform.runner import Runner

TARGET = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:example-AbCdEf"


class TestSecretManagerSecretPolicyAnyPrincipal(unittest.TestCase):
    def test_uses_upstream_evaluator(self):
        conf = {"secret_arn": [TARGET], "policy": [{"Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"
        }]}]}
        with patch("checkov.terraform.checks.resource.aws.SecretManagerSecretPolicyAnyPrincipal.ResourcePolicyDocument",
                   wraps=ResourcePolicyDocument) as evaluator:
            self.assertEqual(check.scan_resource_conf(conf), CheckResult.FAILED)
            evaluator.assert_called_once()

    def test_value_grants_and_policy_forms(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
        private = {**public, "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"}}
        for name, statements, expected in (
            ("read", [public], CheckResult.FAILED),
            ("write", [{**public, "Action": "secretsmanager:PutSecretValue"}], CheckResult.FAILED),
            ("update value", [{**public, "Action": "secretsmanager:UpdateSecret"}], CheckResult.FAILED),
            ("service wildcard", [{**public, "Action": "secretsmanager:*"}], CheckResult.FAILED),
            ("all actions", [{**public, "Action": "*"}], CheckResult.FAILED),
            ("case insensitive", [{**public, "Action": "SecretsManager:Get*"}], CheckResult.FAILED),
            ("public second", [private, public], CheckResult.FAILED),
            ("AWS wildcard", [{**public, "Principal": {"AWS": "*"}}], CheckResult.FAILED),
            ("AWS list", [{**public, "Principal": {"AWS": ["123456789012", "*"]}}], CheckResult.FAILED),
            ("private role", [private], CheckResult.PASSED),
            ("specific service", [{**public, "Principal": {"Service": "s3.amazonaws.com"}}], CheckResult.PASSED),
            ("deny only", [{**public, "Effect": "Deny"}], CheckResult.PASSED),
            ("describe metadata", [{**public, "Action": "secretsmanager:DescribeSecret"}], CheckResult.UNKNOWN),
            ("policy administration", [{**public, "Action": "secretsmanager:PutResourcePolicy"}], CheckResult.UNKNOWN),
            ("batch permission alone", [{**public, "Action": "secretsmanager:BatchGetSecretValue"}], CheckResult.UNKNOWN),
            ("batch plus per-secret read", [{**public, "Action": ["secretsmanager:BatchGetSecretValue", "secretsmanager:GetSecretValue"]}], CheckResult.FAILED),
            ("unresolved principal", [{**public, "Principal": "${var.principal}"}], CheckResult.UNKNOWN),
            ("invalid partial principal", [{**public, "Principal": {"AWS": "arn:aws:iam::*:role/app"}}], CheckResult.UNKNOWN),
            ("invalid service wildcard", [{**public, "Principal": {"Service": "*"}}], CheckResult.UNKNOWN),
            ("missing action", [{"Effect": "Allow", "Principal": "*", "Resource": "*"}], CheckResult.UNKNOWN),
            ("malformed statement", ["invalid"], CheckResult.UNKNOWN),
        ):
            for policy in ({"Statement": statements}, json.dumps({"Statement": statements})):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [policy]}), expected)
        self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [{"Statement": public}]}), CheckResult.FAILED)

    def test_public_policy_block_is_not_confirmed_exposure_or_safety(self):
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
        for flag, expected in (
            (False, CheckResult.FAILED), ("false", CheckResult.FAILED), (None, CheckResult.FAILED),
            (True, CheckResult.UNKNOWN), ("true", CheckResult.UNKNOWN),
            ("${var.block_public_policy}", CheckResult.UNKNOWN), (0, CheckResult.UNKNOWN),
        ):
            with self.subTest(flag=flag):
                self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [policy], "block_public_policy": [flag]}), expected)
        private = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
        self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [private], "block_public_policy": [True]}), CheckResult.PASSED)

    def test_conditions_and_denies_remain_unknown(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
        for condition in (
            {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}},
            {"StringEquals": {"aws:SourceVpce": "vpce-example"}},
            {"ForAllValues:StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}},
            {"StringEquals": "malformed"},
        ):
            with self.subTest(condition=condition):
                policy = {"Statement": [{**public, "Condition": condition}]}
                self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [policy]}), CheckResult.UNKNOWN)
        denial = {**public, "Effect": "Deny", "Condition": {"StringNotEquals": {"aws:SourceVpce": "vpce-example"}}}
        for statements in ([public, denial], [denial, public]):
            self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [{"Statement": statements}]}), CheckResult.UNKNOWN)

    def test_not_action_and_target_matching(self):
        grant = {"Effect": "Allow", "Principal": "*", "NotAction": "s3:*", "Resource": "*"}
        bucket = "arn:aws:s3:::example-bucket/*"
        for name, statement, expected in (
            ("foreign service excluded", grant, CheckResult.FAILED),
            ("read excluded still permits write", {**grant, "NotAction": "secretsmanager:GetSecretValue"}, CheckResult.FAILED),
            ("all secrets excluded", {**grant, "NotAction": "secretsmanager:*"}, CheckResult.PASSED),
            ("all actions excluded", {**grant, "NotAction": "*"}, CheckResult.PASSED),
            ("target ARN", {**grant, "Resource": TARGET}, CheckResult.FAILED),
            ("target pattern", {**grant, "Resource": "arn:aws:secretsmanager:*:123456789012:secret:example-*"}, CheckResult.FAILED),
            ("literal bracket is not a character class", {**grant, "Resource": TARGET.replace("example", "exampl[e]")}, CheckResult.UNKNOWN),
            ("literal bracket is not negation", {**grant, "Resource": TARGET.replace("example", "exampl[!x]")}, CheckResult.UNKNOWN),
            ("question-mark wildcard", {**grant, "Resource": TARGET.replace("example", "exampl?")}, CheckResult.FAILED),
            ("bracket sibling cannot hide target", {**grant, "Resource": [TARGET.replace("example", "exampl[e]"), TARGET]}, CheckResult.FAILED),
            ("other secret", {**grant, "Resource": TARGET.replace("example", "other")}, CheckResult.UNKNOWN),
            ("target then other service", {**grant, "Resource": [TARGET, bucket]}, CheckResult.FAILED),
            ("other service then target", {**grant, "Resource": [bucket, TARGET]}, CheckResult.FAILED),
            ("unknown sibling", {**grant, "Resource": ["${var.arn}", TARGET]}, CheckResult.FAILED),
            ("unresolved scope", {**grant, "Resource": "${var.arn}"}, CheckResult.UNKNOWN),
            ("non-secret scope", {**grant, "Resource": bucket}, CheckResult.UNKNOWN),
            ("malformed resource", {**grant, "Resource": [TARGET, None]}, CheckResult.UNKNOWN),
            ("both action elements", {**grant, "Action": "secretsmanager:*"}, CheckResult.UNKNOWN),
            ("unknown action", {**grant, "NotAction": "${var.actions}"}, CheckResult.UNKNOWN),
            ("NotResource", {**grant, "NotResource": "*"}, CheckResult.UNKNOWN),
        ):
            for policy in ({"Statement": [statement]}, json.dumps({"Statement": [statement]})):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [policy]}), expected)
        reference = "${aws_secretsmanager_secret.example.arn}"
        policy = {"Statement": [{**grant, "Resource": reference}]}
        self.assertEqual(check.scan_resource_conf({"secret_arn": [reference], "policy": [policy]}), CheckResult.FAILED)

    def test_runner_grants_blocks_and_disabled_resources(self):
        resources = {
            "public": ('"*"', "false", '"secretsmanager:GetSecretValue"'),
            "blocked": ('"*"', "true", '"secretsmanager:GetSecretValue"'),
            "private": ('{ AWS = "123456789012" }', "true", '"secretsmanager:GetSecretValue"'),
            "metadata": ('"*"', "false", '"secretsmanager:DescribeSecret"'),
        }
        blocks = []
        for name, (principal, flag, action) in resources.items():
            blocks.append(f'''resource "aws_secretsmanager_secret_policy" "{name}" {{
  secret_arn = "{TARGET}"
  block_public_policy = {flag}
  policy = jsonencode({{
    Statement = [{{ Effect = "Allow", Principal = {principal}, Action = {action}, Resource = "*" }}]
  }})
}}''')
        blocks.append(f'''resource "aws_secretsmanager_secret_policy" "disabled" {{
  count = 0
  secret_arn = "{TARGET}"
  policy = jsonencode({{
    Statement = [{{ Effect = "Allow", Principal = "*", Action = "secretsmanager:GetSecretValue", Resource = "*" }}]
  }})
}}''')
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "main.tf").write_text("\n".join(blocks))
            runner = Runner()
            report = runner.run(root_folder=folder, runner_filter=RunnerFilter(checks=[check.id]))
            self.assertEqual(report.parsing_errors, [])
            self.assertEqual({r.resource for r in report.failed_checks}, {"aws_secretsmanager_secret_policy.public"})
            self.assertEqual({r.resource for r in report.passed_checks}, {"aws_secretsmanager_secret_policy.private"})
            unknown = {}
            for definition in runner.definitions.values():
                for resource in definition.get("resource", []):
                    for name, conf in resource.get("aws_secretsmanager_secret_policy", {}).items():
                        if name in {"blocked", "metadata"}:
                            unknown[name] = check.scan_resource_conf(conf)
            self.assertEqual(unknown, {"blocked": CheckResult.UNKNOWN, "metadata": CheckResult.UNKNOWN})

    def test_missing_and_unparsed_inputs(self):
        for conf in ({}, {"secret_arn": [TARGET]}, {"secret_arn": [TARGET], "policy": [""]}):
            self.assertEqual(check.scan_resource_conf(conf), CheckResult.UNKNOWN)
        for value in ("not JSON", "data.aws_iam_policy_document.secret.json", "${jsonencode(var.policy)}"):
            with self.subTest(value=value):
                self.assertEqual(check.scan_resource_conf({"secret_arn": [TARGET], "policy": [value]}), CheckResult.UNKNOWN)
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]}
        self.assertEqual(check.scan_resource_conf({"secret_arn": ["arn:aws:s3:::example-bucket"], "policy": [policy]}), CheckResult.UNKNOWN)
