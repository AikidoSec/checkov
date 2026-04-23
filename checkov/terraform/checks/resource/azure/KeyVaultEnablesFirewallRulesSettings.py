from typing import Any

from checkov.terraform.checks.resource.base_resource_value_check import BaseResourceValueCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class KeyVaultEnablesFirewallRulesSettings(BaseResourceValueCheck):
    def __init__(self):
        name = "Ensure that key vault allows firewall rules settings"
        id = "CKV_AZURE_109"
        supported_resources = ['azurerm_key_vault']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def get_inspected_key(self):
        return "network_acls/[0]/default_action"

    def get_expected_value(self):
        return "Deny"

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        if not public_network_access or not isinstance(public_network_access, list):
            return super().scan_resource_conf(conf)
        
        if public_network_access[0] is False:
            return CheckResult.PASSED

        return super().scan_resource_conf(conf)

check = KeyVaultEnablesFirewallRulesSettings()