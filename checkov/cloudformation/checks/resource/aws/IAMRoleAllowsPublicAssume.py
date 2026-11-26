from typing import Dict, Any

from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.common.util.iam_role_trust import scan_iam_role_trust_policy


class IAMRoleAllowsPublicAssume(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure IAM role allows only specific services or principals to assume it"
        id = "CKV_AWS_60"
        supported_resources = ("AWS::IAM::Role",)
        categories = (CheckCategories.IAM,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: Dict[str, Any]) -> CheckResult:
        self.evaluated_keys = ["Properties/AssumeRolePolicyDocument/Statement"]
        properties = conf.get("Properties")
        if properties is None:
            return CheckResult.PASSED
        if not isinstance(properties, dict):
            return CheckResult.UNKNOWN
        return scan_iam_role_trust_policy(properties.get("AssumeRolePolicyDocument"))


check = IAMRoleAllowsPublicAssume()
