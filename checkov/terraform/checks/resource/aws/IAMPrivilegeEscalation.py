from __future__ import annotations

from typing import List, Dict, Any, Union, TYPE_CHECKING

from checkov.common.models.enums import CheckResult
from checkov.terraform.checks.resource.base_cloudsplaining_resource_iam_check import \
    BaseTerraformCloudsplainingResourceIAMCheck

if TYPE_CHECKING:
    from cloudsplaining.scan.policy_document import PolicyDocument


class ResourceCloudSplainingPrivilegeEscalation(BaseTerraformCloudsplainingResourceIAMCheck):
    def __init__(self) -> None:
        name = "Ensure IAM policies does not allow privilege escalation"
        id = "CKV_AWS_286"
        super().__init__(name=name, id=id)

    def scan_resource_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        result = super().scan_resource_conf(conf)
        if result != CheckResult.PASSED or self.entity_type != "aws_iam_role_policy" or "role" not in conf:
            return result
        role = conf["role"]
        if not isinstance(role, list) or len(role) != 1 or not isinstance(role[0], str) or not role[0]:
            return CheckResult.UNKNOWN
        policy = self.policy_document_cache.get(self.cache_key)
        if policy is None:
            return result

        # An inline grant on all roles includes the role carrying the policy;
        # unlike modifying another role, this does not require AssumeRole.
        self_modification_actions = {"iam:putrolepolicy", "iam:attachrolepolicy"}
        has_self_grant = any(
            statement.effect_allow
            and statement.has_resource_wildcard
            and self_modification_actions.intersection(action.lower() for action in statement.expanded_actions)
            for statement in policy.statements
        )
        if not has_self_grant:
            return result
        if any({"NotAction", "NotResource"}.intersection(statement.json) for statement in policy.statements):
            return CheckResult.UNKNOWN
        unrestricted = {action.lower() for action in policy.all_allowed_unrestricted_actions}
        self.evaluated_keys = ["policy"]
        if self_modification_actions.intersection(unrestricted):
            return CheckResult.FAILED
        # Conditions and potentially protective Denies suppress library analysis;
        # do not report those grants as proven safe or as confirmed escalation.
        return CheckResult.UNKNOWN

    def cloudsplaining_analysis(self, policy: PolicyDocument) -> Union[List[str], List[Dict[str, Any]]]:
        return policy.allows_privilege_escalation


check = ResourceCloudSplainingPrivilegeEscalation()
