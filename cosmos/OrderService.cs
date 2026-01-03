public interface IOrderService : ICosmosDbService<Order>
{
    Task<IEnumerable<Order>> GetOrdersByStatusAsync(string status);
    Task<bool> UpdateOrderStatusAsync(string id, string status);
    Task<Order> GetByOrderNumberAsync(string orderNumber);
}

public class OrderService : CosmosDbServiceBase<Order>, IOrderService
{
    public OrderService(
        CosmosClient cosmosClient,
        IConfiguration configuration,
        IUserContextAccessor userContextAccessor)
        : base(
            cosmosClient,
            configuration["CosmosDb:DatabaseName"],
            configuration["CosmosDb:OrdersContainerName"],
            userContextAccessor)
    {
    }

    protected override void OnBeforeCreate(Order item)
    {
        base.OnBeforeCreate(item);

        // Auto-generate order number if not provided
        if (string.IsNullOrEmpty(item.OrderNumber))
        {
            item.OrderNumber = $"ORD-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString().Substring(0, 6).ToUpper()}";
        }

        // Set initial status
        if (string.IsNullOrEmpty(item.Status))
        {
            item.Status = "Pending";
        }
    }

    public async Task<IEnumerable<Order>> GetOrdersByStatusAsync(string status)
    {
        return await GetAllAsync($"c.status = '{status}'");
    }

    public async Task<bool> UpdateOrderStatusAsync(string id, string status)
    {
        var fieldsToUpdate = new Dictionary<string, object>
        {
            { "status", status }
        };

        return await PatchFieldsAsync(id, fieldsToUpdate);
    }

    public async Task<Order> GetByOrderNumberAsync(string orderNumber)
    {
        var userContext = GetUserContext();

        var query = new QueryDefinition(
            "SELECT * FROM c WHERE c.sponsorId = @sponsorId " +
            "AND c.subscriberId = @subscriberId " +
            "AND c.orderNumber = @orderNumber")
            .WithParameter("@sponsorId", userContext.SponsorId)
            .WithParameter("@subscriberId", userContext.SubscriberId)
            .WithParameter("@orderNumber", orderNumber);

        var results = await QueryAsync(query);
        return results.FirstOrDefault();
    }
}