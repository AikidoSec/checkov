from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.common.util.iam_role_trust import scan_iam_role_trust_policy
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from typing import List


class IAMRoleAllowsPublicAssume(BaseResourceCheck):

    def __init__(self):
        name = "Ensure IAM role allows only specific services or principals to assume it"
        id = "CKV_AWS_60"
        supported_resources = ['aws_iam_role']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'assume_role_policy' not in conf:
            return CheckResult.PASSED
        policy = conf['assume_role_policy']
        if not isinstance(policy, list) or len(policy) != 1:
            return CheckResult.UNKNOWN
        return scan_iam_role_trust_policy(policy[0])

    def get_evaluated_keys(self) -> List[str]:
        return ['assume_role_policy']


check = IAMRoleAllowsPublicAssume()
