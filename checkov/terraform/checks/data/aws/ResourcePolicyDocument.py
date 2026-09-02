from __future__ import annotations

from typing import Any, TYPE_CHECKING

from checkov.common.models.enums import CheckResult
from checkov.common.util.type_forcers import force_list
from checkov.terraform.checks.data.base_cloudsplaining_data_iam_check import BaseTerraformCloudsplainingDataIAMCheck

if TYPE_CHECKING:
    from cloudsplaining.scan.policy_document import PolicyDocument


class ResourcePolicyDocument(BaseTerraformCloudsplainingDataIAMCheck):
    def __init__(self) -> None:
        name = 'Ensure no IAM policies documents allow "*" as a statement\'s resource for restrictable actions'
        id = "CKV_AWS_356"
        super().__init__(name=name, id=id)

    def scan_data_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        if self._is_kms_key_policy(conf):
            # in a KMS key policy the resource "*" means "this KMS key", so it can't be narrowed down
            return CheckResult.PASSED

        return super().scan_data_conf(conf)

    def cloudsplaining_analysis(self, policy: PolicyDocument) -> list[str] | list[dict[str, Any]]:
        return policy.all_allowed_unrestricted_actions

    @staticmethod
    def _is_kms_key_policy(conf: dict[str, list[Any]]) -> bool:
        statements = conf.get("statement")
        if not statements:
            return False

        for statements_block in statements:
            for statement in force_list(statements_block):
                if not isinstance(statement, dict):
                    return False
                # only resource policies can define principals, identity policies can't
                if not (statement.get("principals") or statement.get("not_principals")):
                    return False
                actions = statement.get("actions") or statement.get("not_actions")
                if not actions:
                    return False
                if not all(
                    isinstance(action, str) and action.lower().startswith("kms:")
                    for action in force_list(actions[0])
                ):
                    return False

        return True


check = ResourcePolicyDocument()
