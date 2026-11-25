from __future__ import annotations

import fnmatch
from typing import Any

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.common.util.type_forcers import extract_policy_dict
from checkov.common.util.var_utils import is_terraform_variable_dependent
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

# Use currently documented messaging actions, not legacy sns:Receive entries.
# https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-language-api-permissions-reference.html
_MESSAGING_ACTIONS = ("sns:publish", "sns:subscribe")


class SNSTopicPolicyAnyPrincipal(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure SNS topic policies do not allow unrestricted public publishing or subscription"
        id = "CKV_AWS_169"
        supported_resources = ("aws_sns_topic_policy", "aws_sns_topic")
        categories = (CheckCategories.GENERAL_SECURITY,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: dict[str, Any]) -> CheckResult:
        raw_policy = conf.get("policy")
        if isinstance(raw_policy, list):
            if not raw_policy:
                return CheckResult.PASSED
            if len(raw_policy) != 1:
                return CheckResult.UNKNOWN
            raw_policy = raw_policy[0]
        if raw_policy in (None, ""):
            return CheckResult.PASSED
        policy = extract_policy_dict(raw_policy)
        if not isinstance(policy, dict):
            return CheckResult.UNKNOWN
        statements = policy.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
            return CheckResult.UNKNOWN

        has_deny = any(s.get("Effect") == "Deny" for s in statements)
        unknown = False
        for statement in statements:
            if "Condition" in statement:
                condition = statement["Condition"]
                if not isinstance(condition, dict):
                    unknown = True
                    continue
                if any(not isinstance(value, dict) for value in condition.values()):
                    unknown = True
                    continue
            if statement.get("Effect") == "Deny":
                continue
            if statement.get("Effect") != "Allow" or "NotPrincipal" in statement:
                unknown = True
                continue
            principal = statement.get("Principal")
            is_service = isinstance(principal, dict) and "AWS" not in principal
            if isinstance(principal, dict):
                principal = principal.get("AWS", principal.get("Service"))
            principals = _principal_values(principal)
            if principals is None:
                unknown = True
                continue
            if "*" not in principals:
                continue
            has_condition = "Condition" in statement and statement["Condition"] != {}
            cannot_assess = is_service or has_deny or has_condition
            if cannot_assess:
                unknown = True
                continue
            grant = _allows_messaging(statement)
            if grant is True:
                return CheckResult.FAILED
            if grant is None:
                unknown = True
        return CheckResult.UNKNOWN if unknown else CheckResult.PASSED

    def get_evaluated_keys(self) -> list[str]:
        return ["policy"]


def _principal_values(value: Any) -> list[str] | None:
    values = value if isinstance(value, list) else [value]
    if not values:
        return None
    for item in values:
        if not isinstance(item, str) or not item or is_terraform_variable_dependent(item):
            return None
        # IAM permits Principal '*' but not partially wildcarded Principal ARNs.
        if "*" in item and item != "*":
            return None
    return values


def _allows_messaging(statement: dict[str, Any]) -> bool | None:
    uses_not_action = "NotAction" in statement
    if "NotResource" in statement:
        return None
    if uses_not_action and "Action" in statement:
        return None
    raw_actions = statement.get("NotAction" if uses_not_action else "Action")
    actions = raw_actions if isinstance(raw_actions, list) else [raw_actions]
    if not actions:
        return None
    patterns = []
    for action in actions:
        if not isinstance(action, str) or not action or is_terraform_variable_dependent(action):
            return None
        pattern = action.lower()
        if pattern != "*":
            service, separator, operation = pattern.partition(":")
            if not separator or not service or not operation:
                return None
            if not service.isascii() or not service.replace("-", "").isalnum():
                return None
            is_ascii_operation = operation.isascii()
            has_valid_characters = all(c.isalnum() or c in "*?" for c in operation)
            valid_operation = is_ascii_operation and has_valid_characters
            if not valid_operation:
                return None
        patterns.append(pattern)
    resources = statement.get("Resource")
    resources = resources if isinstance(resources, list) else [resources]
    # SNS topic policies permit only one resource per statement. Do not infer
    # deployed exposure from a mixed-resource policy SNS documents as unsupported.
    if len(resources) != 1:
        return None
    resource = resources[0]
    if not isinstance(resource, str) or not resource:
        return None
    excludes_all_sns = "*" in patterns or "sns:*" in patterns
    if uses_not_action and excludes_all_sns:
        return False
    if is_terraform_variable_dependent(resource):
        # Explicit SNS actions are assessed in the attached topic's context.
        # NotAction needs a known topic scope to evaluate its complement.
        if uses_not_action:
            return None
    elif not _known_topic_scope(resource):
        return None
    for action in _MESSAGING_ACTIONS:
        matches = any(fnmatch.fnmatchcase(action, pattern) for pattern in patterns)
        is_granted = not matches if uses_not_action else matches
        if is_granted:
            return True
    # No publishing/subscription grant is proven; do not label metadata access or
    # otherwise unsupported permissions as public messaging exposure.
    return None


def _known_topic_scope(value: str) -> bool:
    if value == "*":
        return True
    parts = value.split(":", 5)
    if len(parts) != 6:
        return False
    prefix, partition, service, region, account, topic = parts
    if prefix != "arn" or not partition.startswith("aws") or service != "sns":
        return False
    if not region or not account or not topic:
        return False
    if account == "*":
        return True
    return len(account) == 12 and account.isascii() and account.isdigit()


check = SNSTopicPolicyAnyPrincipal()
