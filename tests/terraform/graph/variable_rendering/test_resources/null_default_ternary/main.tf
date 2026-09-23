variable "subnet_ids" {
  type    = list(string)
  default = null
}

variable "fallback_subnet_id" {
  type    = string
  default = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/pe"
}

variable "provided_subnet_ids" {
  type    = list(string)
  default = ["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/provided"]
}

variable "max_pods" {
  type    = number
  default = null
}

variable "tls_version" {
  type    = string
  default = null
}

variable "max_pods_extra" {
  type    = number
  default = 7
}

resource "azurerm_key_vault" "null_default" {
  name = "kv-null-default"

  network_acls {
    default_action             = "Deny"
    virtual_network_subnet_ids = var.subnet_ids == null ? [var.fallback_subnet_id] : var.subnet_ids
  }
}

resource "azurerm_key_vault" "provided_list" {
  name = "kv-provided-list"

  network_acls {
    default_action             = "Deny"
    virtual_network_subnet_ids = var.provided_subnet_ids == null ? [var.fallback_subnet_id] : var.provided_subnet_ids
  }
}

resource "azurerm_key_vault" "direct_null" {
  name = "kv-direct-null"

  network_acls {
    default_action             = "Deny"
    virtual_network_subnet_ids = var.subnet_ids
  }
}

resource "azurerm_kubernetes_cluster" "null_compare" {
  name = "aks-null-compare"

  default_node_pool {
    name     = "syspool"
    max_pods = var.max_pods == null ? 51 : 49
  }
}

resource "azurerm_storage_account" "null_string" {
  name            = "stnull"
  min_tls_version = var.tls_version
}

resource "azurerm_storage_account" "top_level" {
  name                     = "sttop"
  account_replication_type = var.max_pods == null ? "LRS" : "GRS"
}

resource "azurerm_storage_account" "longer_name" {
  name         = "stlong"
  account_kind = null == var.max_pods_extra ? var.max_pods : var.max_pods_extra
}
