from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any

from checkov.common.models.enums import CheckResult
from checkov.common.util.type_forcers import extract_policy_dict


def _is_literal(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and not any(
        marker in value for marker in ("${", "%{", "{{")
    )


def _allows_assume_role(statement: dict[str, Any]) -> bool | None:
    if ("Action" in statement) == ("NotAction" in statement):
        return None
    not_action = "NotAction" in statement
    actions = statement["NotAction"] if not_action else statement["Action"]
    actions = actions if isinstance(actions, list) else [actions]
    if not actions or any(not _is_literal(action) or "[" in action for action in actions):
        return None
    # Action names are case-insensitive; IAM supports * and ? wildcards.
    matches = any(fnmatchcase("sts:assumerole", action.lower()) for action in actions)
    return not matches if not_action else matches


def _is_public_principal(statement: dict[str, Any]) -> bool | None:
    if "NotPrincipal" in statement:
        return None
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return None
    principal = {key: value for key, value in principal.items() if key not in ("__startline__", "__endline__")}
    if not principal or principal.keys() - {"AWS", "Service", "Federated"}:
        return None
    public = False
    for kind, values in principal.items():
        values = values if isinstance(values, list) else [values]
        if not values:
            return None
        for value in values:
            if not _is_literal(value):
                return None
            if kind == "AWS" and value == "*":
                public = True
            elif "*" in value or "?" in value:
                # Partial wildcard principal ARNs are unsupported by IAM.
                return None
    return public


def scan_iam_role_trust_policy(policy: Any) -> CheckResult:
    """CKV_AWS_60: identify clear public AssumeRole grants, not effective permissions."""
    if policy is None or policy == "" or policy == {}:
        # Preserve the rule's existing behavior for absent/empty policies.
        return CheckResult.PASSED
    policy_dict = extract_policy_dict(policy)
    if not isinstance(policy_dict, dict):
        return CheckResult.UNKNOWN
    if not policy_dict:
        return CheckResult.PASSED
    statements = policy_dict.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return CheckResult.UNKNOWN

    public_allow = False
    unknown = False
    potential_deny = False
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny"):
            # An unparsed statement could contain a protective Deny.
            unknown = potential_deny = True
            continue
        relevant = _allows_assume_role(statement)
        if statement["Effect"] == "Deny":
            potential_deny |= relevant is not False
            continue
        if relevant is False:
            continue
        if relevant is None:
            unknown = True
            continue
        public = _is_public_principal(statement)
        if public is None:
            unknown = True
        elif public:
            condition = statement.get("Condition", {})
            if isinstance(condition, dict):
                condition = {
                    key: value for key, value in condition.items() if key not in ("__startline__", "__endline__")
                }
            if condition != {}:
                # Do not guess whether MFA, External ID, organization, ARN,
                # network, or other conditions restrict the grant sufficiently.
                unknown = True
            else:
                public_allow = True

    if public_allow:
        return CheckResult.UNKNOWN if potential_deny else CheckResult.FAILED
    return CheckResult.UNKNOWN if unknown else CheckResult.PASSED
