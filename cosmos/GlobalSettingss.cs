// Different Partition Keys

public interface IGlobalSettingsService : ICosmosDbService<GlobalSettings>
{
    Task<GlobalSettings> GetByKeyAsync(string settingKey);
    Task<IEnumerable<GlobalSettings>> GetAllForTenantAsync();
}

public class GlobalSettingsService : CosmosDbServiceBase<GlobalSettings>, IGlobalSettingsService
{
    public GlobalSettingsService(
        CosmosClient cosmosClient,
        IConfiguration configuration,
        IUserContextAccessor userContextAccessor)
        : base(
            cosmosClient,
            configuration["CosmosDb:DatabaseName"],
            configuration["CosmosDb:GlobalSettingsContainerName"],
            userContextAccessor)
    {
    }

    // Override to use tenantId as partition key
    protected override PartitionKey GetPartitionKey()
    {
        var userContext = GetUserContext();
        return new PartitionKey(userContext.SponsorId); // Using SponsorId as TenantId
    }

    protected override PartitionKey GetPartitionKeyForItem(GlobalSettings item)
    {
        return new PartitionKey(item.TenantId);
    }

    protected override void OnBeforeCreate(GlobalSettings item)
    {
        base.OnBeforeCreate(item);

        var userContext = GetUserContext();

        // Set tenantId from context
        if (string.IsNullOrEmpty(item.TenantId))
        {
            item.TenantId = userContext.SponsorId;
        }
    }

    // Override GetAllAsync for different query structure
    public override async Task<IEnumerable<GlobalSettings>> GetAllAsync(string additionalFilter = null)
    {
        var userContext = GetUserContext();

        var queryText = "SELECT * FROM c WHERE c.tenantId = @tenantId";

        if (!string.IsNullOrEmpty(additionalFilter))
        {
            queryText += $" AND ({additionalFilter})";
        }

        var query = new QueryDefinition(queryText)
            .WithParameter("@tenantId", userContext.SponsorId);

        return await ExecuteQueryAsync(query);
    }

    public async Task<GlobalSettings> GetByKeyAsync(string settingKey)
    {
        var userContext = GetUserContext();

        var query = new QueryDefinition(
            "SELECT * FROM c WHERE c.tenantId = @tenantId " +
            "AND c.settingKey = @settingKey")
            .WithParameter("@tenantId", userContext.SponsorId)
            .WithParameter("@settingKey", settingKey);

        var results = await QueryAsync(query);
        return results.FirstOrDefault();
    }

    public async Task<IEnumerable<GlobalSettings>> GetAllForTenantAsync()
    {
        return await GetAllAsync();
    }
}