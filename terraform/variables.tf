variable "resource_group_name" {
  description = "Name of the resource group containing the Cosmos DB account"
  type        = string
}

variable "cosmosdb_account_name" {
  description = "Name of the existing Cosmos DB account"
  type        = string
}

variable "database_name" {
  description = "Name of the Cosmos DB SQL database"
  type        = string
  default     = "cfc_clover_db"
}
