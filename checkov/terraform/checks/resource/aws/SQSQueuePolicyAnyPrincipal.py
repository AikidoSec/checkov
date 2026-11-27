from __future__ import annotations

import fnmatch
from typing import Any

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.common.util.type_forcers import extract_policy_dict
from checkov.common.util.var_utils import is_terraform_variable_dependent
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

# Queue-scoped IAM actions that SQS permits sharing across accounts. Administrative
# actions such as SetQueueAttributes/DeleteQueue cannot grant cross-account access.
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html
_SHARED_QUEUE_ACTIONS = (
    "sqs:changemessagevisibility", "sqs:deletemessage", "sqs:getqueueattributes", "sqs:getqueueurl",
    "sqs:listdeadlettersourcequeues", "sqs:purgequeue", "sqs:receivemessage", "sqs:sendmessage",
)


class SQSQueuePolicyAnyPrincipal(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure SQS queue policy is not public by only allowing specific services or principals to access it"
        id = "CKV_AWS_168"
        supported_resources = ("aws_sqs_queue_policy", "aws_sqs_queue")
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
            if statement.get("Effect") == "Deny":
                continue
            if statement.get("Effect") != "Allow" or "NotPrincipal" in statement:
                unknown = True
                continue
            principal = statement.get("Principal")
            is_service = isinstance(principal, dict) and "AWS" not in principal
            if isinstance(principal, dict):
                principal = principal.get("AWS", principal.get("Service"))
            principals = _strings(principal)
            if principals is None:
                unknown = True
                continue
            if "*" not in principals:
                continue
            # Service wildcards are not valid IAM principals. Conditional grants
            # and potentially protective Denies need separate semantic analysis.
            has_condition = "Condition" in statement and statement["Condition"] != {}
            cannot_assess = is_service or has_deny or has_condition
            if cannot_assess:
                unknown = True
                continue
            grant = _allows_shared_queue_action(statement)
            if grant is True:
                return CheckResult.FAILED
            if grant is None:
                unknown = True
        return CheckResult.UNKNOWN if unknown else CheckResult.PASSED

    def get_evaluated_keys(self) -> list[str]:
        return ["policy"]


def _strings(value: Any) -> list[str] | None:
    values = value if isinstance(value, list) else [value]
    if not values:
        return None
    for item in values:
        if not isinstance(item, str) or not item or is_terraform_variable_dependent(item):
            return None
        # Partial wildcards in Principal ARNs are invalid. Action/Resource
        # wildcards are checked separately and do not use this helper.
        if "*" in item and item != "*":
            return None
    return values


def _allows_shared_queue_action(statement: dict[str, Any]) -> bool | None:
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
            if not operation.isascii() or not all(c.isalnum() or c in "*?" for c in operation):
                return None
        patterns.append(pattern)

    excludes_all_sqs = "*" in patterns or "sqs:*" in patterns
    if uses_not_action and excludes_all_sqs:
        return False

    resources = statement.get("Resource")
    resources = resources if isinstance(resources, list) else [resources]
    if not resources:
        return None
    has_queue_scope = False
    for resource in resources:
        if not isinstance(resource, str) or not resource:
            return None
        if is_terraform_variable_dependent(resource):
            # An explicit SQS Action is evaluated in the attached queue policy's
            # context. NotAction needs a known scope to evaluate its complement.
            if not uses_not_action:
                has_queue_scope = True
            continue
        if _known_queue_scope(resource):
            has_queue_scope = True
            continue
        # Resource entries are ORed. A valid non-queue ARN cannot cancel an
        # applicable queue grant in another entry, but malformed values stay unknown.
        parts = resource.split(":", 5)
        if len(parts) != 6:
            return None
        if parts[0] != "arn" or not parts[1] or not parts[2] or not parts[5]:
            return None
    if not has_queue_scope:
        return None
    for action in _SHARED_QUEUE_ACTIONS:
        matches = any(fnmatch.fnmatchcase(action, pattern) for pattern in patterns)
        is_granted = not matches if uses_not_action else matches
        if is_granted:
            return True
    # Unsupported/owner-only actions and otherwise unproven complements are not
    # a public-access finding, but neither are they a complete permissions verdict.
    return None


def _known_queue_scope(value: str) -> bool:
    if value == "*":
        return True
    parts = value.split(":", 5)
    if len(parts) != 6:
        return False
    prefix, partition, service, region, account, queue = parts
    if prefix != "arn" or not partition.startswith("aws") or service != "sqs":
        return False
    if not region or not account or not queue:
        return False
    if account == "*":
        return True
    return len(account) == 12 and account.isascii() and account.isdigit()


check = SQSQueuePolicyAnyPrincipal()
