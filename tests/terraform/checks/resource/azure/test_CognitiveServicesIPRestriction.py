import unittest

import hcl2

from checkov.terraform.checks.resource.azure.CognitiveServicesIPRestriction import check
from checkov.common.models.enums import CheckResult


class TestCognitiveServicesIPRestriction(unittest.TestCase):
    def test_success_private_account(self):
        hcl_res = hcl2.loads("""
            resource "azurerm_cognitive_account" "example" {
              name                          = "example-account"
              location                      = "eastus"
              resource_group_name           = "example-rg"
              kind                          = "Face"
              sku_name                      = "S0"
              public_network_access_enabled = false
            }
        """)
        resource_conf = hcl_res['resource'][0]['azurerm_cognitive_account']['example']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)
    
    def test_success_false_with_acls(self):
        hcl_res = hcl2.loads("""
            resource "azurerm_cognitive_account" "example" {
              name                          = "example-account"
              location                      = "eastus"
              resource_group_name           = "example-rg"
              kind                          = "Face"
              sku_name                      = "S0"
              public_network_access_enabled = false

              network_acls {
                default_action = "Allow"
                ip_rules       = []
              }
            }
        """)
        resource_conf = hcl_res['resource'][0]['azurerm_cognitive_account']['example']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

    def test_success_deny_with_ips(self):
        hcl_res = hcl2.loads("""
            resource "azurerm_cognitive_account" "example" {
              name                          = "example-account"
              location                      = "eastus"
              resource_group_name           = "example-rg"
              kind                          = "Face"
              sku_name                      = "S0"
              public_network_access_enabled = true

              network_acls {
                default_action = "Deny"
                ip_rules       = ["203.0.113.50", "198.51.100.0/24"]
              }
            }
        """)
        resource_conf = hcl_res['resource'][0]['azurerm_cognitive_account']['example']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

    def test_failure_deny_missing_ips(self):
        hcl_res = hcl2.loads("""
            resource "azurerm_cognitive_account" "example" {
              name                          = "example-account"
              location                      = "eastus"
              resource_group_name           = "example-rg"
              kind                          = "Face"
              sku_name                      = "S0"
              public_network_access_enabled = true

              network_acls {
                default_action = "Deny"
              }
            }
        """)
        resource_conf = hcl_res['resource'][0]['azurerm_cognitive_account']['example']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.FAILED, scan_result)

    def test_failure_deny_empty_ips(self):
        hcl_res = hcl2.loads("""
            resource "azurerm_cognitive_account" "example" {
              name                          = "example-account"
              location                      = "eastus"
              resource_group_name           = "example-rg"
              kind                          = "Face"
              sku_name                      = "S0"
              public_network_access_enabled = true

              network_acls {
                default_action = "Deny"
                ip_rules       = []
              }
            }
        """)
        resource_conf = hcl_res['resource'][0]['azurerm_cognitive_account']['example']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.FAILED, scan_result)

    def test_success_missing_acls_handled_by_134(self):
        # The rule evaluates as a Pass because there are no Network ACLs to evaluate
        # This prevents duplicate failures, as CKV_AZURE_134 will already flag this as a failure.
        hcl_res = hcl2.loads("""
            resource "azurerm_cognitive_account" "example" {
              name                          = "example-account"
              location                      = "eastus"
              resource_group_name           = "example-rg"
              kind                          = "Face"
              sku_name                      = "S0"
              public_network_access_enabled = true
            }
        """)
        resource_conf = hcl_res['resource'][0]['azurerm_cognitive_account']['example']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

    def test_success_allow_action_handled_by_134(self):
        # The rule evaluates as a Pass because the default_action is Allow
        # This prevents duplicate failures, as CKV_AZURE_134 will already flag this as a failure.
        hcl_res = hcl2.loads("""
            resource "azurerm_cognitive_account" "example" {
              name                          = "example-account"
              location                      = "eastus"
              resource_group_name           = "example-rg"
              kind                          = "Face"
              sku_name                      = "S0"
              public_network_access_enabled = true

              network_acls {
                default_action = "Allow"
                ip_rules       = ["203.0.113.50"]
              }
            }
        """)
        resource_conf = hcl_res['resource'][0]['azurerm_cognitive_account']['example']
        scan_result = check.scan_resource_conf(conf=resource_conf)
        self.assertEqual(CheckResult.PASSED, scan_result)

if __name__ == '__main__':
    unittest.main()
