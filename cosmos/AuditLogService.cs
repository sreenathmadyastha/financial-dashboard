// No Partition Keys

public interface IAuditLogService : ICosmosDbService<AuditLog>
{
    Task<IEnumerable<AuditLog>> GetLogsByEntityAsync(string entityType, string entityId);
    Task<IEnumerable<AuditLog>> GetLogsByActionAsync(string action);
}

public class AuditLogService : CosmosDbServiceBase<AuditLog>, IAuditLogService
{
    public AuditLogService(
        CosmosClient cosmosClient,
        IConfiguration configuration,
        IUserContextAccessor userContextAccessor)
        : base(
            cosmosClient,
            configuration["CosmosDb:DatabaseName"],
            configuration["CosmosDb:AuditLogsContainerName"],
            userContextAccessor)
    {
    }

    // Override partition key logic - AuditLog doesn't use sponsorId/subscriberId
    protected override PartitionKey GetPartitionKey()
    {
        // Use a single partition or different logic
        return new PartitionKey("audit-logs");
    }

    protected override PartitionKey GetPartitionKeyForItem(AuditLog item)
    {
        // Could partition by date, entity type, etc.
        return new PartitionKey(item.EntityType ?? "unknown");
    }

    // Override GetAllAsync since AuditLog doesn't have sponsorId/subscriberId
    public override async Task<IEnumerable<AuditLog>> GetAllAsync(string additionalFilter = null)
    {
        var queryText = "SELECT * FROM c";

        if (!string.IsNullOrEmpty(additionalFilter))
        {
            queryText += $" WHERE {additionalFilter}";
        }

        var query = new QueryDefinition(queryText);
        return await ExecuteQueryAsync(query);
    }

    public async Task<IEnumerable<AuditLog>> GetLogsByEntityAsync(string entityType, string entityId)
    {
        var query = new QueryDefinition(
            "SELECT * FROM c WHERE c.entityType = @entityType " +
            "AND c.entityId = @entityId " +
            "ORDER BY c.createdDate DESC")
            .WithParameter("@entityType", entityType)
            .WithParameter("@entityId", entityId);

        return await QueryAsync(query);
    }

    public async Task<IEnumerable<AuditLog>> GetLogsByActionAsync(string action)
    {
        return await GetAllAsync($"c.action = '{action}'");
    }
}