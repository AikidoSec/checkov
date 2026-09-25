from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class CognitiveServicesDisablesPublicNetwork(BaseResourceCheck):
    def __init__(self):
        name = "Ensure that Cognitive Services accounts disable public network access or use Network ACLs"
        id = "CKV_AZURE_134"
        supported_resources = ('azurerm_cognitive_account',)
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
                return CheckResult.PASSED
        
        return CheckResult.FAILED

check = CognitiveServicesDisablesPublicNetwork()
