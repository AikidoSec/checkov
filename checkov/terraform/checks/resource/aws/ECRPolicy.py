from __future__ import annotations

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
            if not principals or any(not isinstance(p, str) or not p or is_terraform_variable_dependent(p)
                                     or ("*" in p and p != "*") for p in principals):
                unknown = True
                continue
            if "*" not in principals:
                continue
            # Even an apparently restrictive condition may be unresolved or use
            # unsafe operators. Leave it unknown rather than blindly pass or fail.
            if ("Condition" in statement and statement["Condition"] != {}) or has_deny:
                unknown = True
                continue
            actions = statement.get("Action")
            actions = actions if isinstance(actions, list) else [actions]
            if not actions or any(not isinstance(a, str) or not a or is_terraform_variable_dependent(a)
                                  or (a != "*" and (not a.lower().startswith("ecr:") or a.lower() == "ecr:")) for a in actions):
                unknown = True
                continue
            return CheckResult.FAILED
        return CheckResult.UNKNOWN if unknown else CheckResult.PASSED

    def get_evaluated_keys(self) -> list[str]:
        return ["policy"]


check = ECRPolicy()
