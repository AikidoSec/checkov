from typing import Any
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_value_check import BaseResourceValueCheck

class KeyVaultEnablesFirewallRulesSettings(BaseResourceValueCheck):
    def __init__(self):
        name = "Ensure that key vault allows firewall rules settings"
        id = "CKV_AZURE_109"
        supported_resources = ['Microsoft.KeyVault/vaults']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def get_inspected_key(self):
        return "properties/networkAcls/defaultAction"

    def get_expected_value(self):
        return "Deny"

   def scan_resource_conf(self, conf: dict[str, Any]) -> CheckResult:
        properties = conf.get("properties")        
        if properties and isinstance(properties, dict):
            public_network_access = properties.get("publicNetworkAccess")
            if isinstance(public_network_access, str) and public_network_access.lower() == "disabled":
                return CheckResult.PASSED

        return super().scan_resource_conf(conf)

check = KeyVaultEnablesFirewallRulesSettings()