from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.common.util.var_utils import is_terraform_variable_dependent
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class LambdaFunctionIsNotPublic(BaseResourceCheck):
    def __init__(self) -> None:
        """
        PCI DSS v3.2.1/1.2.1, PCI DSS v3.2.1/1.3.1, PCI DSS v3.2.1/1.3.2, PCI DSS v3.2.1/1.3.4, PCI DSS v3.2.1/7.2.1,
        NIST.800-53.r5 AC-21, NIST.800-53.r5 AC-3, NIST.800-53.r5 AC-3(7), NIST.800-53.r5 AC-4, NIST.800-53.r5 AC-4(21),
        NIST.800-53.r5 AC-6, NIST.800-53.r5 SC-7, NIST.800-53.r5 SC-7(11), NIST.800-53.r5 SC-7(16), NIST.800-53.r5 SC-7(20),
        NIST.800-53.r5 SC-7(21), NIST.800-53.r5 SC-7(3), NIST.800-53.r5 SC-7(4), NIST.800-53.r5 SC-7(9)
        Lambda function policies should prohibit public access
        """

        name = "Ensure Lambda permissions do not allow unrestricted public invocation"
        id = "CKV_AWS_301"
        supported_resources = ("aws_lambda_permission",)
        categories = (CheckCategories.GENERAL_SECURITY,)
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf: dict[str, Any]) -> CheckResult:
        principal = _scalar(conf.get("principal"))
        if not isinstance(principal, str) or not principal or is_terraform_variable_dependent(principal):
            return CheckResult.UNKNOWN
        if "*" in principal and principal != "*":
            return CheckResult.UNKNOWN
        if principal != "*":
            # Service-to-service confused-deputy risks are separate from public
            # invocation. Do not flag every service principal without a source ARN.
            return CheckResult.PASSED

        action = _scalar(conf.get("action"))
        if not isinstance(action, str) or action.lower() not in {"lambda:invokefunction", "lambda:*", "*"}:
            return CheckResult.UNKNOWN

        # Function URL conditions and Alexa tokens need separate assessment.
        # Do not label these restricted invocation modes as unrestricted access.
        unknown_constraint = False
        for key in ("function_url_auth_type", "invoked_via_function_url", "event_source_token"):
            value = _scalar(conf.get(key))
            if value is None:
                continue
            is_function_url_invocation = key == "invoked_via_function_url"
            is_disabled = value is False or value == "false"
            if is_function_url_invocation and is_disabled:
                continue
            unknown_constraint = True

        for key in ("source_arn", "source_account", "principal_org_id"):
            value = _scalar(conf.get(key))
            if value is None:
                continue
            if not isinstance(value, str) or not value or is_terraform_variable_dependent(value):
                unknown_constraint = True
                continue
            if key == "source_account" and _is_account_id(value):
                return CheckResult.PASSED
            if key == "principal_org_id" and _is_org_id(value):
                return CheckResult.PASSED
            if key == "source_arn" and _source_arn_restricts(value):
                return CheckResult.PASSED
            unknown_constraint = True

        return CheckResult.UNKNOWN if unknown_constraint else CheckResult.FAILED

    def get_evaluated_keys(self) -> list[str]:
        return ["principal", "action", "source_arn", "source_account", "principal_org_id",
                "function_url_auth_type", "invoked_via_function_url", "event_source_token"]


def _scalar(value: Any) -> Any:
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def _is_account_id(value: str) -> bool:
    return len(value) == 12 and value.isascii() and value.isdigit()


def _is_org_id(value: str) -> bool:
    if not value.startswith("o-"):
        return False
    identifier = value[2:]
    if not 10 <= len(identifier) <= 32:
        return False
    if not identifier.isascii() or not identifier.isalnum():
        return False
    return identifier == identifier.lower()


def _source_arn_restricts(value: str) -> bool:
    # Split only the five ARN separators: colons inside the resource are data.
    parts = value.split(":", 5)
    if len(parts) != 6:
        return False
    prefix, partition, service, region, account, resource = parts
    if prefix != "arn" or not partition.startswith("aws") or not service or not resource:
        return False
    for namespace in (partition, service):
        name = namespace.replace("-", "")
        if not name.isascii() or not name.isalnum() or namespace != namespace.lower():
            return False

    # SourceArn uses StringLike. A fixed account limits the source even when
    # region/resource components contain wildcards; don't hard-code region names.
    if _is_account_id(account):
        return True
    if service != "s3" or region or account:
        return False

    # S3 bucket ARNs have no account. Accept only a literal bucket name, not a
    # wildcard pattern that unrelated accounts could match with their own buckets.
    bucket = resource
    if not 3 <= len(bucket) <= 63 or not bucket.isascii() or bucket != bucket.lower():
        return False
    if not bucket[0].isalnum() or not bucket[-1].isalnum():
        return False
    return bucket.replace("-", "").replace(".", "").isalnum()


check = LambdaFunctionIsNotPublic()
