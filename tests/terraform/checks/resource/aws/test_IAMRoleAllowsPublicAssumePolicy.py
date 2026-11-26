import json
import tempfile
import unittest
from pathlib import Path

import yaml

from checkov.cloudformation.checks.resource.aws.IAMRoleAllowsPublicAssume import check as cfn_check
from checkov.cloudformation.runner import Runner as CfnRunner
from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.checks.resource.aws.IAMRoleAllowsPublicAssume import check as tf_check
from checkov.terraform.runner import Runner as TfRunner


def allow(principal="*", action="sts:AssumeRole", **extra):
    return {"Effect": "Allow", "Principal": principal, "Action": action, **extra}


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


class TestIAMRoleTrust(unittest.TestCase):
    def cases(self):
        failed, passed, unknown = CheckResult.FAILED, CheckResult.PASSED, CheckResult.UNKNOWN
        role = "arn:aws:iam::123456789012:role/scanner-example"
        root = "arn:aws:iam::123456789012:root"
        public = allow()
        deny = {**public, "Effect": "Deny"}
        cases = [
            ("root_wildcard", policy(public), failed),
            ("aws_wildcard", policy(allow({"AWS": "*"})), failed),
            ("aws_list", policy(allow({"AWS": [root, "*"]})), failed),
            ("wildcard_first", policy(allow({"AWS": ["*", role]})), failed),
            ("statement_object", {"Statement": allow()}, failed),
            ("action_list", policy(allow(action=["sts:TagSession", "sts:AssumeRole"])), failed),
            ("all_actions", policy(allow(action="*")), failed),
            ("sts_actions", policy(allow(action="sts:*")), failed),
            ("assume_prefix", policy(allow(action="sts:Assume*")), failed),
            ("action_case", policy(allow(action="STS:ASSUMEROLE")), failed),
            ("action_question", policy(allow(action="sts:AssumeRol?")), failed),
            ("empty_condition", policy(allow(Condition={})), failed),
            ("unrelated_conditioned_allow", policy(allow({"AWS": role}, Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}), public), failed),
            ("conditioned_public_does_not_mask", policy(allow(Condition={"StringEquals": {"sts:ExternalId": "example"}}), public), failed),
            ("unrelated_deny", policy(public, {**deny, "Action": "sts:TagSession"}), failed),
            ("specific_root", policy(allow({"AWS": root})), passed),
            ("account_id", policy(allow({"AWS": "123456789012"})), passed),
            ("specific_role", policy(allow({"AWS": role})), passed),
            ("specific_role_condition", policy(allow({"AWS": role}, Condition={"StringEquals": {"sts:ExternalId": "example"}})), passed),
            ("role_list", policy(allow({"AWS": [root, role]})), passed),
            ("iam_user", policy(allow({"AWS": "arn:aws:iam::123456789012:user/scanner-example"})), passed),
            ("assumed_role", policy(allow({"AWS": "arn:aws:sts::123456789012:assumed-role/scanner-example/session"})), passed),
            ("govcloud_role", policy(allow({"AWS": "arn:aws-us-gov:iam::123456789012:role/scanner-example"})), passed),
            ("china_root", policy(allow({"AWS": "arn:aws-cn:iam::123456789012:root"})), passed),
            ("service", policy(allow({"Service": "lambda.amazonaws.com"})), passed),
            ("service_list", policy(allow({"Service": ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]})), passed),
            ("oidc", policy(allow({"Federated": "arn:aws:iam::123456789012:oidc-provider/example.com"}, action="sts:AssumeRoleWithWebIdentity")), passed),
            ("saml", policy(allow({"Federated": "arn:aws:iam::123456789012:saml-provider/example"}, action="sts:AssumeRoleWithSAML")), passed),
            ("unrelated_action", policy(allow(action="sts:TagSession")), passed),
            ("deny_only", policy(deny), passed),
            ("no_statements", policy(), passed),
            ("empty_string", "", passed),
            ("absent", None, passed),
            ("empty_object", {}, passed),
            ("protective_deny_after", policy(public, deny), unknown),
            ("protective_deny_before", policy(deny, public), unknown),
            ("conditional_deny", policy(public, {**deny, "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-example"}}}), unknown),
            ("scoped_deny", policy(public, {**deny, "Principal": {"AWS": role}}), unknown),
            ("not_action", policy(allow(NotAction="sts:TagSession")), unknown),
            ("not_principal", policy(allow(NotPrincipal={"AWS": role})), unknown),
            ("missing_action", policy({"Effect": "Allow", "Principal": "*"}), unknown),
            ("empty_action", policy(allow(action=[])), unknown),
            ("invalid_action", policy(allow(action=[None])), unknown),
            ("unresolved_action", policy(allow(action="${var.action}")), unknown),
            ("intrinsic_action", policy(allow(action={"Ref": "TrustAction"})), unknown),
            ("missing_effect", policy({"Principal": "*", "Action": "sts:AssumeRole"}), unknown),
            ("invalid_effect", policy({**public, "Effect": "allow"}), unknown),
            ("missing_principal", policy({"Effect": "Allow", "Action": "sts:AssumeRole"}), unknown),
            ("empty_principal", policy(allow("")), unknown),
            ("invalid_principal_list", policy(allow(["*"])), unknown),
            ("empty_aws_list", policy(allow({"AWS": []})), unknown),
            ("invalid_aws", policy(allow({"AWS": [None]})), unknown),
            ("unresolved_principal", policy(allow({"AWS": "${var.trusted_role}"})), unknown),
            ("intrinsic_principal", policy(allow({"AWS": {"Fn::GetAtt": ["TrustedRole", "Arn"]}})), unknown),
            ("partial_wildcard", policy(allow({"AWS": "arn:aws:iam::123456789012:role/*"})), unknown),
            ("partial_wildcard_with_public", policy(allow({"AWS": ["*", "arn:aws:iam::123456789012:role/*"]})), unknown),
            ("wildcard_service", policy(allow({"Service": "*"})), unknown),
            ("wildcard_federated", policy(allow({"Federated": "*"})), unknown),
            ("unknown_principal_type", policy(allow({"Other": "*"})), unknown),
            ("invalid_principal_key", policy(allow({1: "*"})), unknown),
            ("invalid_statement", {"Statement": ["unresolved", public]}, unknown),
            ("invalid_statement_after", {"Statement": [public, "unresolved"]}, unknown),
            ("invalid_statements_type", {"Statement": "${var.statements}"}, unknown),
            ("missing_statements", {"Version": "2012-10-17"}, unknown),
            ("invalid_json", "{broken", unknown),
            ("json_list", "[]", unknown),
            ("unresolved_document", "${data.aws_iam_policy_document.trust.json}", unknown),
            ("intrinsic_document", {"Fn::If": ["UsePublicTrust", policy(public), policy()]}, unknown),
        ]
        for name, condition in (
            ("organization", {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}),
            ("principal_arn", {"ArnLike": {"aws:PrincipalArn": role}}),
            ("source_account", {"StringEquals": {"aws:SourceAccount": "123456789012"}}),
            ("mfa", {"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
            ("external_id", {"StringEquals": {"sts:ExternalId": "scanner-example"}}),
            ("network", {"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}}),
            ("time", {"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}}),
            ("if_exists", {"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-example"}}),
            ("invalid", None),
            ("expression", "${var.condition}"),
        ):
            cases.append((f"condition_{name}", policy(allow(Condition=condition)), unknown))
            cases.append((f"aws_condition_{name}", policy(allow({"AWS": "*"}, Condition=condition)), unknown))
        return cases

    def test_both_frameworks_native_and_json(self):
        for name, document, expected in self.cases():
            documents = [document, json.dumps(document)] if isinstance(document, dict) else [document]
            for value in documents:
                for framework, check, conf in (
                    ("terraform", tf_check, {"assume_role_policy": [value]}),
                    ("cloudformation", cfn_check, {"Properties": {"AssumeRolePolicyDocument": value}}),
                ):
                    with self.subTest(name=name, framework=framework, json=isinstance(value, str)):
                        self.assertEqual(check.scan_resource_conf(conf), expected)

    def test_invalid_framework_wrappers(self):
        for value in ("${var.trust}", {}, [], [policy(allow()), policy(allow())]):
            with self.subTest(terraform=value):
                self.assertEqual(tf_check.scan_resource_conf({"assume_role_policy": value}), CheckResult.UNKNOWN)
        self.assertEqual(cfn_check.scan_resource_conf({"Properties": []}), CheckResult.UNKNOWN)

    def test_both_runners(self):
        names = {
            "root_wildcard", "aws_list", "statement_object", "empty_condition", "specific_root", "service", "oidc",
            "condition_organization", "protective_deny_after",
        }
        cases = [case for case in self.cases() if case[0] in names]
        with tempfile.TemporaryDirectory() as folder:
            tf_dir, cfn_dir = Path(folder, "terraform"), Path(folder, "cloudformation")
            tf_dir.mkdir()
            cfn_dir.mkdir()
            blocks = []
            resources = {}
            for name, document, _ in cases:
                blocks.append(f'resource "aws_iam_role" "{name}" {{\nname = "scanner-example-{name}"\nassume_role_policy = jsonencode({json.dumps(document)})\n}}')
                resources[name] = {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": document}}
            Path(tf_dir, "main.tf").write_text("\n".join(blocks))
            Path(cfn_dir, "template.yaml").write_text(yaml.safe_dump({"Resources": resources}))
            for framework, runner, directory, prefix in (
                ("terraform", TfRunner(), tf_dir, "aws_iam_role"),
                ("cloudformation", CfnRunner(), cfn_dir, "AWS::IAM::Role"),
            ):
                with self.subTest(framework=framework):
                    report = runner.run(root_folder=str(directory), runner_filter=RunnerFilter(checks=[tf_check.id]))
                    self.assertEqual(report.parsing_errors, [])
                    self.assertEqual({r.resource for r in report.failed_checks}, {f"{prefix}.{name}" for name, _, result in cases if result == CheckResult.FAILED})
                    self.assertEqual({r.resource for r in report.passed_checks}, {f"{prefix}.{name}" for name, _, result in cases if result == CheckResult.PASSED})
                    self.assertEqual(report.skipped_checks, [])
