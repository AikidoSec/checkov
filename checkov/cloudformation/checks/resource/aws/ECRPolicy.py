from __future__ import annotations

import json
import fnmatch
import logging
import re
from typing import Any

from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.consts import SLS_DEFAULT_VAR_PATTERN
from checkov.common.models.enums import CheckResult, CheckCategories


class ECRPolicy(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure ECR policy is not set to public"
        id = "CKV_AWS_32"
        supported_resources = ("AWS::ECR::Repository",)
        categories = (CheckCategories.GENERAL_SECURITY,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: dict[str, Any]) -> CheckResult:
        """
            Looks for public * policy for ecr repository:
            https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html
        :param conf: aws_ecr_repository configuration
        :return: <CheckResult>
        """
        self.evaluated_keys = ["Properties/RepositoryPolicyText/Statement"]
        properties = conf.get("Properties")
        if not properties or not isinstance(properties, dict):
            return CheckResult.PASSED
        policy_text = properties.get("RepositoryPolicyText")
        if not policy_text:
            return CheckResult.PASSED
        if isinstance(policy_text, str):
            try:
                policy_text = json.loads(str(policy_text))
            except json.decoder.JSONDecodeError as e:
                if re.match(SLS_DEFAULT_VAR_PATTERN, str(policy_text)):
                    # Case where the template is a sub-CFN configuration inside a serverless configuration,
                    # and the policy is a variable expression
                    logging.info(f"Encountered variable expression {str(policy_text)} in resource ${self.entity_path}")
                else:
                    logging.error(
                        f"Malformed policy configuration {str(policy_text)} of resource {self.entity_path}\n{e}"
                    )
                return CheckResult.UNKNOWN
        if not isinstance(policy_text, dict):
            return CheckResult.UNKNOWN
        statements = policy_text.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
            return CheckResult.UNKNOWN
        has_deny = any(s.get("Effect") == "Deny" for s in statements)
        unknown = False
        for statement in statements:
            # Deny statements do not grant access and may protect an Allow.
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
                or "${" in p
                or p.startswith("Ref.")
                or ("*" in p and p != "*")
                for p in principals
            )
            if invalid_principals:
                unknown = True
                continue
            if "*" not in principals:
                continue
            # Keep the same conservative boundary as Terraform. Evaluating the
            # effect of conditions and Denies is outside this rule's scope.
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
                or "${" in a
                or a.startswith("Ref.")
                or (a != "*" and not re.fullmatch(r"[\w-]+:[\w*?]+", a))
                for a in actions
            )
            if invalid_actions:
                unknown = True
                continue
            if uses_not_action:
                # Evaluate exclusions only when a repository action can be proven
                # allowed. Do not expand this into an effective-permissions engine.
                exclusions = [a.lower() for a in actions]
                if "*" in exclusions or "ecr:*" in exclusions:
                    continue
                resources = statement.get("Resource")
                resources = resources if isinstance(resources, list) else [resources]
                known_scope = resources and "NotResource" not in statement and all(
                    isinstance(r, str)
                    and "${" not in r
                    and not r.startswith("Ref.")
                    and (r == "*" or re.fullmatch(r"arn:[^:]+:ecr:[^:]+:[^:]+:repository/.+", r))
                    for r in resources
                )
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


check = ECRPolicy()
