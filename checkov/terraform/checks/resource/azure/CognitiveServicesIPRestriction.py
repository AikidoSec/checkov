from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

OPEN_IP_RULES = ("0.0.0.0/0", "::/0", "*")


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
        if network_acls and isinstance(network_acls, list):
            acl = network_acls[0]
            default_action = acl.get("default_action", [""])[0]

            if isinstance(default_action, str) and default_action.lower() == "deny":
                ip_rules = self._normalize_ip_rules(acl.get("ip_rules"))
                if self._has_specific_ip_rules(ip_rules):
                    return CheckResult.PASSED

                return CheckResult.FAILED

        # If network ACLs are completely missing we return PASSED as CKV_AZURE_134 will already flag it as FAILED
        return CheckResult.PASSED

    @staticmethod
    def _normalize_ip_rules(ip_rules):
        # [["1.2.3.4"]] or ["${var.x}"] / ["${concat(...)}"] -> ["1.2.3.4", "5.6.7.8"]
        if not ip_rules or not isinstance(ip_rules, list):
            return ip_rules

        if len(ip_rules) == 1:
            only = ip_rules[0]
            if isinstance(only, list):
                return only
            if isinstance(only, str) and ("${" in only or only.startswith(("concat(", "tolist(", "compact(", "var."))):
                return only

        return ip_rules

    @staticmethod
    def _has_specific_ip_rules(ip_rules) -> bool:
        if not ip_rules:
            return False

        if isinstance(ip_rules, list):
            specific_ips = [ip for ip in ip_rules if isinstance(ip, str) and ip]
            if not specific_ips:
                return False
            if any(ip.lower() in OPEN_IP_RULES for ip in specific_ips):
                return False
            return True

        if isinstance(ip_rules, str):
            return ip_rules.lower() not in OPEN_IP_RULES

        return False


check = CognitiveServicesIPRestriction()
