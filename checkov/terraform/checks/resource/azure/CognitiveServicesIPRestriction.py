from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

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
            
            if default_action == "Deny":
                ip_rules = acl.get("ip_rules", [[]])[0]
                if isinstance(ip_rules, list) and len(ip_rules) > 0:
                    return CheckResult.PASSED
                
                return CheckResult.FAILED
        
        # If network ACLs are completely missing we return PASSED as CKV_AZURE_134 will already flag it as FAILED
        return CheckResult.PASSED

check = CognitiveServicesIPRestriction()