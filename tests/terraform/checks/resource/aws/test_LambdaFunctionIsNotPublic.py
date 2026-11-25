import os
import tempfile
import unittest
from pathlib import Path

from checkov.common.models.enums import CheckResult
from checkov.runner_filter import RunnerFilter
from checkov.terraform.runner import Runner
from checkov.terraform.checks.resource.aws.LambdaFunctionIsNotPublic import check


class TestLambdaFunctionIsNotPublic(unittest.TestCase):

    def test(self):
        runner = Runner()
        current_dir = os.path.dirname(os.path.realpath(__file__))

        test_files_dir = os.path.join(current_dir, "example_LambdaFunctionIsNotPublic")
        report = runner.run(root_folder=test_files_dir, runner_filter=RunnerFilter(checks=[check.id]))
        summary = report.get_summary()

        passing_resources = {
            "aws_lambda_permission.pass",
            # The original "fail" fixture has a concrete source ARN and is restricted.
            "aws_lambda_permission.fail",
        }
        failing_resources = set()

        passed_check_resources = set([c.resource for c in report.passed_checks])
        failed_check_resources = set([c.resource for c in report.failed_checks])

        self.assertEqual(summary["passed"], len(passing_resources))
        self.assertEqual(summary["failed"], len(failing_resources))
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["parsing_errors"], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)

    def test_public_invocation_and_constraints(self):
        public = {"principal": ["*"], "action": ["lambda:InvokeFunction"]}
        for name, overrides, expected in (
            ("bare public", {}, CheckResult.FAILED),
            ("wildcard action", {"action": ["lambda:*"]}, CheckResult.FAILED),
            ("all actions", {"action": ["*"]}, CheckResult.FAILED),
            ("case insensitive action", {"action": ["lambda:invokefunction"]}, CheckResult.FAILED),
            ("qualifier does not restrict callers", {"qualifier": ["live"]}, CheckResult.FAILED),
            ("service principal", {"principal": ["s3.amazonaws.com"]}, CheckResult.PASSED),
            ("account principal", {"principal": ["123456789012"]}, CheckResult.PASSED),
            ("role principal", {"principal": ["arn:aws:iam::123456789012:role/app"]}, CheckResult.PASSED),
            ("trusted principal wildcard action", {"principal": ["123456789012"], "action": ["lambda:*"]}, CheckResult.PASSED),
            ("source account", {"source_account": ["123456789012"]}, CheckResult.PASSED),
            ("organization", {"principal_org_id": ["o-1234567890"]}, CheckResult.PASSED),
            ("source ARN", {"source_arn": ["arn:aws:events:eu-west-1:123456789012:rule/daily"]}, CheckResult.PASSED),
            ("account scoped ARN wildcard", {"source_arn": ["arn:aws:events:eu-west-1:123456789012:rule/*"]}, CheckResult.PASSED),
            ("fixed S3 bucket", {"source_arn": ["arn:aws:s3:::example-bucket"]}, CheckResult.PASSED),
            ("numeric S3 bucket", {"source_arn": ["arn:aws:s3:::12345"]}, CheckResult.PASSED),
            ("China partition", {"source_arn": ["arn:aws-cn:events:cn-north-1:123456789012:rule/daily"]}, CheckResult.PASSED),
            ("GovCloud partition", {"source_arn": ["arn:aws-us-gov:events:us-gov-west-1:123456789012:rule/daily"]}, CheckResult.PASSED),
            ("colons inside resource", {"source_arn": ["arn:aws:logs:eu-west-1:123456789012:log-group:app:log-stream:*"]}, CheckResult.PASSED),
            ("fixed account with wildcard region", {"source_arn": ["arn:aws:execute-api:*:123456789012:api/*"]}, CheckResult.PASSED),
            ("account restricts unknown ARN", {"source_account": ["123456789012"], "source_arn": ["${var.arn}"]}, CheckResult.PASSED),
            ("unresolved principal", {"principal": ["${var.principal}"]}, CheckResult.UNKNOWN),
            ("missing principal", {"principal": []}, CheckResult.UNKNOWN),
            ("empty principal", {"principal": [""]}, CheckResult.UNKNOWN),
            ("invalid partial wildcard principal", {"principal": ["arn:aws:iam::*:root"]}, CheckResult.UNKNOWN),
            ("missing action", {"action": []}, CheckResult.UNKNOWN),
            ("unresolved action", {"action": ["${var.action}"]}, CheckResult.UNKNOWN),
            ("non invocation action", {"action": ["lambda:GetFunction"]}, CheckResult.UNKNOWN),
            ("function URL action", {"action": ["lambda:InvokeFunctionUrl"]}, CheckResult.UNKNOWN),
            ("unresolved source ARN", {"source_arn": ["${aws_s3_bucket.app.arn}"]}, CheckResult.UNKNOWN),
            ("unresolved source account", {"source_account": ["${var.account}"]}, CheckResult.UNKNOWN),
            ("unresolved organization", {"principal_org_id": ["${var.org}"]}, CheckResult.UNKNOWN),
            ("broad source ARN", {"source_arn": ["*"]}, CheckResult.UNKNOWN),
            ("wildcard account ARN", {"source_arn": ["arn:aws:events:eu-west-1:*:rule/daily"]}, CheckResult.UNKNOWN),
            ("wildcard bucket ARN", {"source_arn": ["arn:aws:s3:::example-*"]}, CheckResult.UNKNOWN),
            ("invalid ARN", {"source_arn": ["not-an-arn"]}, CheckResult.UNKNOWN),
            ("incomplete ARN", {"source_arn": ["arn:aws:events:eu-west-1:123456789012"]}, CheckResult.UNKNOWN),
            ("empty ARN resource", {"source_arn": ["arn:aws:events:eu-west-1:123456789012:"]}, CheckResult.UNKNOWN),
            ("invalid ARN prefix", {"source_arn": ["other:aws:events:eu-west-1:123456789012:rule/daily"]}, CheckResult.UNKNOWN),
            ("unsupported partition", {"source_arn": ["arn:other:events:eu-west-1:123456789012:rule/daily"]}, CheckResult.UNKNOWN),
            ("wildcard partition", {"source_arn": ["arn:aws*:events:eu-west-1:123456789012:rule/daily"]}, CheckResult.UNKNOWN),
            ("wildcard service", {"source_arn": ["arn:aws:*:eu-west-1:123456789012:rule/daily"]}, CheckResult.UNKNOWN),
            ("Unicode ARN account", {"source_arn": ["arn:aws:events:eu-west-1:" + "１" * 12 + ":rule/daily"]}, CheckResult.UNKNOWN),
            ("S3 object instead of bucket", {"source_arn": ["arn:aws:s3:::example-bucket/object"]}, CheckResult.UNKNOWN),
            ("short bucket name", {"source_arn": ["arn:aws:s3:::ab"]}, CheckResult.UNKNOWN),
            ("long bucket name", {"source_arn": ["arn:aws:s3:::" + "a" * 64]}, CheckResult.UNKNOWN),
            ("invalid account", {"source_account": ["*"]}, CheckResult.UNKNOWN),
            ("Unicode account", {"source_account": ["１" * 12]}, CheckResult.UNKNOWN),
            ("uppercase organization", {"principal_org_id": ["o-ABCDEFGHIJ"]}, CheckResult.UNKNOWN),
            ("empty source ARN", {"source_arn": [""]}, CheckResult.UNKNOWN),
            ("empty source account", {"source_account": [""]}, CheckResult.UNKNOWN),
            ("empty organization", {"principal_org_id": [""]}, CheckResult.UNKNOWN),
            ("null source ARN is omitted", {"source_arn": [None]}, CheckResult.FAILED),
            ("invalid organization", {"principal_org_id": ["o-*"]}, CheckResult.UNKNOWN),
            ("invalid source type", {"source_arn": [True]}, CheckResult.UNKNOWN),
            ("function URL mode", {"invoked_via_function_url": [True]}, CheckResult.UNKNOWN),
            ("function URL mode false", {"invoked_via_function_url": [False]}, CheckResult.FAILED),
            ("invalid URL mode type", {"invoked_via_function_url": [0]}, CheckResult.UNKNOWN),
            ("function URL authentication", {"function_url_auth_type": ["NONE"]}, CheckResult.UNKNOWN),
            ("event source token", {"event_source_token": ["example-token"]}, CheckResult.UNKNOWN),
            ("event token false is a string", {"event_source_token": ["false"]}, CheckResult.UNKNOWN),
            ("empty event source token", {"event_source_token": [""]}, CheckResult.UNKNOWN),
        ):
            with self.subTest(name=name):
                self.assertEqual(check.scan_resource_conf({**public, **overrides}), expected)

    def test_runner_detects_public_permissions_without_flagging_restricted_ones(self):
        configurations = {
            "public": 'principal = "*"',
            "public_wildcard_action": 'principal = "*"',
            "source_account": 'principal = "*"\n source_account = "123456789012"',
            "service": 'principal = "s3.amazonaws.com"\n source_arn = "arn:aws:s3:::example-bucket"',
            "unknown_source": 'principal = "*"\n source_arn = var.source_arn',
            "disabled": 'principal = "*"\n count = 0',
        }
        blocks = ['variable "source_arn" { type = string }']
        for name, attributes in configurations.items():
            action = "lambda:*" if name == "public_wildcard_action" else "lambda:InvokeFunction"
            blocks.append(f'''resource "aws_lambda_permission" "{name}" {{
  function_name = "scanner-example"
  action = "{action}"
  {attributes}
}}''')
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "main.tf").write_text("\n".join(blocks))
            runner = Runner()
            report = runner.run(root_folder=folder, runner_filter=RunnerFilter(checks=[check.id]))
            self.assertEqual(report.parsing_errors, [])
            self.assertEqual({r.resource for r in report.failed_checks}, {
                "aws_lambda_permission.public", "aws_lambda_permission.public_wildcard_action"})
            self.assertEqual({r.resource for r in report.passed_checks}, {
                "aws_lambda_permission.source_account", "aws_lambda_permission.service"})
            unknown_results = []
            for definition in runner.definitions.values():
                for resource in definition.get("resource", []):
                    conf = resource.get("aws_lambda_permission", {}).get("unknown_source")
                    if conf is not None:
                        unknown_results.append(check.scan_resource_conf(conf))
            self.assertEqual(unknown_results, [CheckResult.UNKNOWN])


if __name__ == '__main__':
    unittest.main()
