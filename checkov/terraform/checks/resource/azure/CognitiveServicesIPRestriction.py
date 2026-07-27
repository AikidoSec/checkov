import re
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

OPEN_IP_RULES = {
    "0.0.0.0/0", "::/0", "*",
    "0.0.0.0/1", "128.0.0.0/1",
    "::0/0", "0::0/0", "0:0:0:0:0:0:0:0/0"
}

UNRESOLVED_VAR_PATTERN = re.compile(r"^(?:\$\{)?[a-zA-Z][a-zA-Z0-9_-]*\.[^}()]+(?:})?$")

class CognitiveServicesIPRestriction(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure that Cognitive Services Network ACLs are configured with specific IP rules"
        id = "CKV_AZURE_AIK_1"
        supported_resources = ("azurerm_cognitive_account",)
        categories = (CheckCategories.NETWORKING,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: dict[str, list[any]]) -> CheckResult:
        public_network_access = conf.get("public_network_access_enabled", [True])
        if not public_network_access[0]:
            return CheckResult.PASSED

        network_acls = conf.get("network_acls")
        # If network ACLs are completely missing we return PASSED as CKV_AZURE_134 will already flag it as FAILED
        if not network_acls:
            return CheckResult.PASSED
        if not isinstance(network_acls, list) or not isinstance(network_acls[0], dict):
            return CheckResult.UNKNOWN

        acl = network_acls[0]
        default_action = acl.get("default_action")
        # Defer missing default_action to CKV_AZURE_134
        if not default_action:
            return CheckResult.PASSED

        if not isinstance(default_action, list):
            return CheckResult.UNKNOWN
            
        # Defer non-Deny actions to CKV_AZURE_134
        if str(default_action[0]).lower() != "deny":
            return CheckResult.PASSED

        ip_rules = acl.get("ip_rules", [])
        
        if isinstance(ip_rules, str):
            ip_rules = [ip_rules]
        elif ip_rules and isinstance(ip_rules, list) and isinstance(ip_rules[0], list):
            ip_rules = ip_rules[0]

        if not isinstance(ip_rules, list):
            return CheckResult.UNKNOWN

        valid_ips = [str(ip).strip() for ip in ip_rules if ip]

        if not valid_ips:
            return CheckResult.FAILED

        for ip in valid_ips:
            if ip.lower() in OPEN_IP_RULES:
                return CheckResult.FAILED
            
            # Fails if the rule is an unresolved terraform variable (e.g. "var.my_ips" or "${var.my_ips}")
            if UNRESOLVED_VAR_PATTERN.match(ip):
                return CheckResult.FAILED

        return CheckResult.PASSED


check = CognitiveServicesIPRestriction()
