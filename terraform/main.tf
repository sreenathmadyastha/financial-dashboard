terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_cosmosdb_account" "existing" {
  name                = var.cosmosdb_account_name
  resource_group_name = var.resource_group_name
}

resource "azurerm_cosmosdb_sql_database" "database" {
  name                = var.database_name
  resource_group_name = var.resource_group_name
  account_name        = data.azurerm_cosmosdb_account.existing.name
}

resource "azurerm_cosmosdb_sql_container" "cfc_clover_main" {
  name                  = "cfc_clover_main"
  resource_group_name   = var.resource_group_name
  account_name          = data.azurerm_cosmosdb_account.existing.name
  database_name         = azurerm_cosmosdb_sql_database.database.name
  partition_key_paths   = ["/sponsorid", "/subscriberid"]
  partition_key_version = 2

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    excluded_path {
      path = "/\"_etag\"/?"
    }
  }
}

resource "azurerm_cosmosdb_sql_container" "cfc_clover_user" {
  name                  = "cfc_clover_user"
  resource_group_name   = var.resource_group_name
  account_name          = data.azurerm_cosmosdb_account.existing.name
  database_name         = azurerm_cosmosdb_sql_database.database.name
  partition_key_paths   = ["/sponsor", "/subscriber", "/businessuserid"]
  partition_key_version = 2

  indexing_policy {
    indexing_mode = "consistent"

    included_path {
      path = "/*"
    }

    excluded_path {
      path = "/\"_etag\"/?"
    }
  }
}
