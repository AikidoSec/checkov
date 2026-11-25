import json
import unittest
from pathlib import Path

from checkov.cloudformation.checks.resource.aws.ECRPolicy import check
from checkov.cloudformation.runner import Runner
from checkov.runner_filter import RunnerFilter
from checkov.common.models.enums import CheckResult


class TestECRPolicy(unittest.TestCase):
    def test_summary(self):
        # given
        test_files_dir = Path(__file__).parent / "example_ECRPolicy"

        # when
        runner = Runner()
        report = runner.run(root_folder=str(test_files_dir), runner_filter=RunnerFilter(checks=[check.id]))

        # then
        summary = report.get_summary()

        passing_resources = {
            "AWS::ECR::Repository.Restricted",
            "AWS::ECR::Repository.vpc16AA8B31E",
        }
        failing_resources = {
            "AWS::ECR::Repository.Public",
        }

        passed_check_resources = {c.resource for c in report.passed_checks}
        failed_check_resources = {c.resource for c in report.failed_checks}

        self.assertEqual(summary['passed'], len(passing_resources))
        self.assertEqual(summary['failed'], len(failing_resources))
        self.assertEqual(summary['skipped'], 0)
        self.assertEqual(summary['parsing_errors'], 0)

        self.assertEqual(passing_resources, passed_check_resources)
        self.assertEqual(failing_resources, failed_check_resources)

        # Preserve explicit coverage of the original conditional fixtures. UNKNOWN
        # is omitted from reports, so check the same rendered resource definitions.
        unknown_resources = {"CondAllPass", "CondAnyPass", "CondEqualsPass"}
        unknown_results = {}
        for definition in runner.definitions.values():
            for name, conf in definition.get("Resources", {}).items():
                if name in unknown_resources:
                    unknown_results[name] = check.scan_resource_conf(conf)
        self.assertEqual({name: CheckResult.UNKNOWN for name in unknown_resources}, unknown_results)

    def test_public_grants_and_safeguards(self):
        public = {"Effect": "Allow", "Principal": "*", "Action": "ecr:BatchGetImage"}
        private = {**public, "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"}}
        deny = {**public, "Effect": "Deny"}
        conditional = {**public, "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-example"}}}
        for name, statements, expected in (
            ("public", [public], CheckResult.FAILED),
            ("public second", [private, public], CheckResult.FAILED),
            ("conditional first", [conditional, public], CheckResult.FAILED),
            ("AWS wildcard", [{**public, "Principal": {"AWS": "*"}}], CheckResult.FAILED),
            ("AWS list", [{**public, "Principal": {"AWS": ["123456789012", "*"]}}], CheckResult.FAILED),
            ("private", [private], CheckResult.PASSED),
            ("service", [{**public, "Principal": {"Service": "codebuild.amazonaws.com"}}], CheckResult.PASSED),
            ("deny only", [deny], CheckResult.PASSED),
            ("conditional", [conditional], CheckResult.UNKNOWN),
            ("allow then deny", [public, deny], CheckResult.UNKNOWN),
            ("deny then allow", [deny, public], CheckResult.UNKNOWN),
            ("endpoint deny", [public, {**deny, "Condition": {
                "StringNotEquals": {"aws:SourceVpce": "vpce-example"}}}], CheckResult.UNKNOWN),
            ("unresolved principal", [{**public, "Principal": {"Ref": "Caller"}}], CheckResult.UNKNOWN),
            ("unresolved action", [{**public, "Action": {"Ref": "Action"}}], CheckResult.UNKNOWN),
            ("missing effect", [{"Principal": "*", "Action": "ecr:*"}], CheckResult.UNKNOWN),
            ("missing action", [{"Effect": "Allow", "Principal": "*"}], CheckResult.UNKNOWN),
            ("missing principal", [{"Effect": "Allow", "Action": "ecr:*"}], CheckResult.UNKNOWN),
            ("invalid statement", ["malformed"], CheckResult.UNKNOWN),
        ):
            for policy in ({"Statement": statements}, json.dumps({"Statement": statements})):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"Properties": {"RepositoryPolicyText": policy}}), expected)

    def test_single_statement_and_unresolved_documents(self):
        statement = {"Effect": "Allow", "Principal": "*", "Action": "ecr:*"}
        self.assertEqual(check.scan_resource_conf({"Properties": {
            "RepositoryPolicyText": {"Statement": statement}}}), CheckResult.FAILED)
        for policy in ({"Fn::GetAtt": ["Policy", "Json"]}, {"Statement": "malformed"}, "[]"):
            with self.subTest(policy=policy):
                self.assertEqual(check.scan_resource_conf({"Properties": {"RepositoryPolicyText": policy}}), CheckResult.UNKNOWN)

    def test_not_action_grants_and_scope(self):
        grant = {"Effect": "Allow", "Principal": "*", "Resource": "*", "NotAction": "s3:*"}
        for name, statement, expected in (
            ("other service excluded", grant, CheckResult.FAILED),
            ("individual ECR action excluded", {**grant, "NotAction": "ecr:BatchGetImage"}, CheckResult.FAILED),
            ("read actions excluded", {**grant, "NotAction": ["ecr:Get*", "ecr:Batch*"]}, CheckResult.FAILED),
            ("all ECR actions excluded", {**grant, "NotAction": "ecr:*"}, CheckResult.PASSED),
            ("all actions excluded", {**grant, "NotAction": "*"}, CheckResult.PASSED),
            ("case insensitive exclusion", {**grant, "NotAction": ["ECR:*", "s3:*"]}, CheckResult.PASSED),
            ("repository ARN", {**grant, "Resource": "arn:aws:ecr:eu-west-1:123456789012:repository/app"}, CheckResult.FAILED),
            ("other resource scope", {**grant, "Resource": "arn:aws:s3:::app/*"}, CheckResult.UNKNOWN),
            ("unresolved scope", {**grant, "Resource": {"Fn::GetAtt": ["Repository", "Arn"]}}, CheckResult.UNKNOWN),
            ("unresolved exclusions", {**grant, "NotAction": {"Ref": "Exclusions"}}, CheckResult.UNKNOWN),
            ("both action elements", {**grant, "Action": "ecr:*"}, CheckResult.UNKNOWN),
            ("malformed exclusions", {**grant, "NotAction": "ecr:"}, CheckResult.UNKNOWN),
            ("no known unexcluded action", {**grant, "NotAction": ["ecr:Batch*", "ecr:Get*", "ecr:Put*", "ecr:Delete*"]}, CheckResult.UNKNOWN),
            ("conditional", {**grant, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}, CheckResult.UNKNOWN),
        ):
            for policy in ({"Statement": [statement]}, json.dumps({"Statement": [statement]})):
                with self.subTest(name=name, string=isinstance(policy, str)):
                    self.assertEqual(check.scan_resource_conf({"Properties": {"RepositoryPolicyText": policy}}), expected)
        policy = {"Statement": [grant, {**grant, "Effect": "Deny"}]}
        self.assertEqual(check.scan_resource_conf({"Properties": {"RepositoryPolicyText": policy}}), CheckResult.UNKNOWN)


if __name__ == '__main__':
    unittest.main()
