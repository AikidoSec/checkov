from __future__ import annotations

import fnmatch
from typing import Any

from cloudsplaining.scan.resource_policy_document import ResourcePolicyDocument

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.common.util.type_forcers import extract_policy_dict
from checkov.common.util.var_utils import is_terraform_variable_dependent
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

_VALUE_ACTIONS = ("secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret")
_IAM_LITERAL_BRACKETS = str.maketrans({"[": "[[]", "]": "[]]"})


class SecretManagerSecretPolicyAnyPrincipal(BaseResourceCheck):
    def __init__(self) -> None:
        # Adapted from upstream PR #7595. Its proposed CKV_AWS_394 is not merged,
        # so retain a fork-specific ID instead of claiming an upstream numeric ID.
        super().__init__(
            name="Ensure Secrets Manager policies do not grant unrestricted access to secret values",
            id="CKV_AWS_AIK_2",
            categories=(CheckCategories.IAM,),
            supported_resources=("aws_secretsmanager_secret_policy",),
        )

    def scan_resource_conf(self, conf: dict[str, Any]) -> CheckResult:
        policy = extract_policy_dict(_scalar(conf.get("policy")))
        target = _scalar(conf.get("secret_arn"))
        if not isinstance(policy, dict) or not isinstance(target, str) or not target:
            return CheckResult.UNKNOWN
        if not is_terraform_variable_dependent(target) and not _secret_arn(target):
            return CheckResult.UNKNOWN
        statements = policy.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
            return CheckResult.UNKNOWN
        has_deny = any(s.get("Effect") == "Deny" for s in statements)
        block = _scalar(conf.get("block_public_policy"))
        public_policies_allowed = block is None or block is False or block == "false"
        unknown = False
        for statement in statements:
            if statement.get("Effect") == "Deny":
                continue
            if statement.get("Effect") != "Allow" or "NotPrincipal" in statement or "NotResource" in statement:
                unknown = True
                continue
            actions = _value_actions(statement)
            if actions is None:
                unknown = True
                continue
            has_condition = "Condition" in statement and statement["Condition"] != {}
            if has_condition:
                # Do not let the shared evaluator's broad condition heuristics
                # classify unresolved or unsupported restrictions as safe/public.
                unknown = True
                continue
            try:
                prepared = {**statement, "Action": actions}
                prepared.pop("NotAction", None)
                analysis = ResourcePolicyDocument(policy={"Statement": [prepared]})
                principals = analysis.statements[0].principals
                if not principals:
                    unknown = True
                    continue
                invalid_principals = any(
                    not isinstance(p, str)
                    or not p
                    or is_terraform_variable_dependent(p)
                    or ("*" in p and p != "*")
                    for p in principals
                )
                service = statement.get("Principal", {})
                service = service.get("Service") if isinstance(service, dict) else None
                service_values = service if isinstance(service, list) else [service]
                if invalid_principals or "*" in service_values:
                    unknown = True
                    continue
                accessible_actions = analysis.internet_accessible_actions
            except (TypeError, AttributeError, KeyError, ValueError):
                unknown = True
                continue
            if not accessible_actions:
                continue
            if has_deny or not public_policies_allowed:
                # BlockPublicPolicy can reject an update; it does not prove an
                # already deployed policy is safe. Neither pass nor fail from it.
                unknown = True
                continue
            if _matches_target(statement.get("Resource"), target):
                return CheckResult.FAILED
            unknown = True
        return CheckResult.UNKNOWN if unknown else CheckResult.PASSED

    def get_evaluated_keys(self) -> list[str]:
        return ["policy", "block_public_policy", "secret_arn"]


def _scalar(value: Any) -> Any:
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def _value_actions(statement: dict[str, Any]) -> list[str] | None:
    uses_not_action = "NotAction" in statement
    if uses_not_action and "Action" in statement:
        return None
    patterns = statement.get("NotAction" if uses_not_action else "Action")
    patterns = patterns if isinstance(patterns, list) else [patterns]
    if not patterns:
        return None
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern or is_terraform_variable_dependent(pattern):
            return None
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
    actions = []
    for action in _VALUE_ACTIONS:
        matches = any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns)
        is_granted = not matches if uses_not_action else matches
        if is_granted:
            actions.append(action)
    excludes_all = uses_not_action and any(p.lower() in {"*", "secretsmanager:*"} for p in patterns)
    if not actions and not excludes_all:
        return None  # no supported value grant, not a complete permissions verdict
    # ResourcePolicyDocument does not implement NotAction. Supply only concrete
    # value actions proven by these patterns; it judges the principal's access.
    return actions


def _matches_target(value: Any, target: str) -> bool:
    resources = value if isinstance(value, list) else [value]
    matches = False
    for resource in resources:
        if not isinstance(resource, str) or not resource:
            return False
        if resource == "*" or resource == target:
            matches = True
        elif is_terraform_variable_dependent(resource):
            continue
        else:
            parts = resource.split(":", 5)
            if len(parts) != 6 or parts[0] != "arn" or not parts[1] or not parts[2] or not parts[5]:
                return False
            # IAM Resource patterns use '*'/'?', not shell bracket classes.
            # Translate once so inserted escapes aren't escaped a second time.
            iam_pattern = resource.translate(_IAM_LITERAL_BRACKETS)
            if _secret_arn(target) and fnmatch.fnmatchcase(target, iam_pattern):
                matches = True
    return matches


def _secret_arn(value: str) -> bool:
    if is_terraform_variable_dependent(value):
        return False
    parts = value.split(":", 5)
    if len(parts) != 6:
        return False
    prefix, partition, service, region, account, resource = parts
    if prefix != "arn" or not partition.startswith("aws") or service != "secretsmanager":
        return False
    if not region or len(account) != 12 or not account.isascii() or not account.isdigit():
        return False
    return resource.startswith("secret:") and len(resource) > len("secret:")


check = SecretManagerSecretPolicyAnyPrincipal()
