from __future__ import annotations

import fnmatch
import re
from typing import Any

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.common.util.type_forcers import extract_policy_dict
from checkov.common.util.var_utils import is_terraform_variable_dependent
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class ECRPolicy(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure ECR policy is not set to public"
        id = "CKV_AWS_32"
        supported_resources = ("aws_ecr_repository_policy",)
        categories = (CheckCategories.GENERAL_SECURITY,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        raw_policy = conf.get("policy")
        if not raw_policy or raw_policy[0] in (None, ""):
            return CheckResult.PASSED
        policy = extract_policy_dict(raw_policy[0])
        if not isinstance(policy, dict):
            return CheckResult.UNKNOWN
        statements = policy.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
            return CheckResult.UNKNOWN

        # A Deny can restrict an otherwise public Allow. Resolving effective IAM
        # permissions is out of scope for this rule; do not report a guessed exposure.
        has_deny = any(s.get("Effect") == "Deny" for s in statements)
        unknown = False
        for statement in statements:
            if statement.get("Effect") == "Deny":
                continue
            if statement.get("Effect") != "Allow" or "NotPrincipal" in statement:
                unknown = True
                continue
            principal = statement.get("Principal")
            if isinstance(principal, dict):
                if "AWS" not in principal and principal.get("Service") == "*":
                    unknown = True
                    continue
                principal = principal.get("AWS", principal.get("Service"))
            principals = principal if isinstance(principal, list) else [principal]
            invalid_principals = not principals or any(
                not isinstance(p, str)
                or not p
                or is_terraform_variable_dependent(p)
                or ("*" in p and p != "*")
                for p in principals
            )
            if invalid_principals:
                unknown = True
                continue
            if "*" not in principals:
                continue
            # Even an apparently restrictive condition may be unresolved or use
            # unsafe operators. Leave it unknown rather than blindly pass or fail.
            if ("Condition" in statement and statement["Condition"] != {}) or has_deny:
                unknown = True
                continue
            uses_not_action = "NotAction" in statement
            if uses_not_action and "Action" in statement:
                unknown = True
                continue
            actions = statement.get("NotAction" if uses_not_action else "Action")
            actions = actions if isinstance(actions, list) else [actions]
            invalid_actions = not actions or any(
                not isinstance(a, str)
                or is_terraform_variable_dependent(a)
                or (a != "*" and not re.fullmatch(r"[\w-]+:[\w*?]+", a))
                for a in actions
            )
            if invalid_actions:
                unknown = True
                continue
            if uses_not_action:
                # NotAction is a complement, not a list of granted actions. An
                # excluded non-ECR service still leaves repository actions allowed.
                exclusions = [a.lower() for a in actions]
                if "*" in exclusions or "ecr:*" in exclusions:
                    continue
                resources = statement.get("Resource")
                resources = resources if isinstance(resources, list) else [resources]
                known_scope = resources and "NotResource" not in statement and all(
                    isinstance(r, str)
                    and not is_terraform_variable_dependent(r)
                    and (r == "*" or re.fullmatch(r"arn:[^:]+:ecr:[^:]+:[^:]+:repository/.+", r))
                    for r in resources
                )
                # A concrete unexcluded repository action proves a grant. This
                # small witness set is not an exhaustive ECR permissions model.
                repository_actions = (
                    "ecr:batchgetimage", "ecr:getdownloadurlforlayer",
                    "ecr:putimage", "ecr:deleterepository",
                )
                has_grant = False
                for action in repository_actions:
                    is_excluded = any(fnmatch.fnmatchcase(action, exclusion) for exclusion in exclusions)
                    if not is_excluded:
                        has_grant = True
                        break
                if not known_scope or not has_grant:
                    unknown = True
                    continue
            elif any(a != "*" and not a.lower().startswith("ecr:") for a in actions):
                unknown = True
                continue
            return CheckResult.FAILED
        return CheckResult.UNKNOWN if unknown else CheckResult.PASSED

    def get_evaluated_keys(self) -> list[str]:
        return ["policy"]


check = ECRPolicy()
