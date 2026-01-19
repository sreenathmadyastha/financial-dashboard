output "cfc_clover_main_container_id" {
  description = "The ID of the cfc_clover_main container"
  value       = azurerm_cosmosdb_sql_container.cfc_clover_main.id
}

output "cfc_clover_user_container_id" {
  description = "The ID of the cfc_clover_user container"
  value       = azurerm_cosmosdb_sql_container.cfc_clover_user.id
}

output "database_id" {
  description = "The ID of the Cosmos DB database"
  value       = azurerm_cosmosdb_sql_database.database.id
}
