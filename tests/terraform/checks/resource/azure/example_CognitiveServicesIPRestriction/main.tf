variable "whitelisted_ip_addresses" {
  type    = list(string)
  default = ["203.0.113.50", "198.51.100.0/24"]
}

variable "empty_whitelisted_ip_addresses" {
  type    = list(string)
  default = []
}

variable "public_accessible_ips" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "kiplot_vpn_public_ip" {
  type    = string
  default = "203.0.113.50/32"
}

variable "ai_allowed_ips" {
  type    = list(string)
  default = ["198.51.100.0/24"]
}

resource "azurerm_cognitive_account" "pass_private" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = false
}

resource "azurerm_cognitive_account" "pass_private_with_acls" {
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

resource "azurerm_cognitive_account" "pass_missing_acls" {
  # Pass here to avoid duplicate failures; CKV_AZURE_134 covers missing ACLs
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true
}

resource "azurerm_cognitive_account" "pass_allow_action" {
  # Pass here to avoid duplicate failures; CKV_AZURE_134 covers Allow
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

resource "azurerm_cognitive_account" "pass_literal_ips" {
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

resource "azurerm_cognitive_account" "pass_lowercase_deny" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "deny"
    ip_rules       = ["203.0.113.50"]
  }
}

resource "azurerm_cognitive_account" "pass_var_ips" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "ComputerVision"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = var.whitelisted_ip_addresses
  }
}

resource "azurerm_cognitive_account" "pass_dynamic_concat" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "AIServices"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = concat([trimsuffix(var.kiplot_vpn_public_ip, "/32")], var.ai_allowed_ips)
  }
}

resource "azurerm_cognitive_account" "fail_unresolved_var_ips" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "ComputerVision"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = var.undefined_whitelisted_ips
  }
}

resource "azurerm_cognitive_account" "fail_missing_ips" {
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

resource "azurerm_cognitive_account" "fail_empty_ips" {
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

resource "azurerm_cognitive_account" "fail_lowercase_deny_empty_ips" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "deny"
    ip_rules       = []
  }
}

resource "azurerm_cognitive_account" "fail_empty_string_ips" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = [""]
  }
}

resource "azurerm_cognitive_account" "fail_open_cidr" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = ["0.0.0.0/0"]
  }
}

resource "azurerm_cognitive_account" "fail_open_cidr_among_valid_ips" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = ["203.0.113.50", "0.0.0.0/0"]
  }
}

resource "azurerm_cognitive_account" "fail_open_ipv6" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = ["::/0"]
  }
}

resource "azurerm_cognitive_account" "fail_open_star" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "Face"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = ["*"]
  }
}

resource "azurerm_cognitive_account" "fail_empty_var_ips" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "ComputerVision"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = var.empty_whitelisted_ip_addresses
  }
}

resource "azurerm_cognitive_account" "fail_public_var_ips" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "ComputerVision"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = var.public_accessible_ips
  }
}

resource "azurerm_cognitive_account" "fail_dynamic_concat_public" {
  name                          = "example-account"
  location                      = "eastus"
  resource_group_name           = "example-rg"
  kind                          = "AIServices"
  sku_name                      = "S0"
  public_network_access_enabled = true

  network_acls {
    default_action = "Deny"
    ip_rules       = concat(["0.0.0.0/0"], var.ai_allowed_ips)
  }
}
