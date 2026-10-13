variable "suffix" {
  type    = string
  default = null
}

variable "name" {
  type    = string
  default = "x"
}

# Inside a quoted template hcl2 keeps the `null` token verbatim instead of converting it to `None`.
resource "azurerm_storage_account" "nested_null" {
  account_replication_type = "${var.suffix == null ? "LRS" : "GRS"}"
}

# Same shape with a set string variable: the compared value must be substituted as a string literal.
resource "azurerm_storage_account" "nested_set" {
  account_replication_type = "${var.name == "x" ? "LRS" : "GRS"}"
}
