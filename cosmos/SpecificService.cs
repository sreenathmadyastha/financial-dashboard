public interface IProductService : ICosmosDbService<Product>
{
    Task<bool> UpdateIsCloverLinkedAsync(string id, bool isCloverLinked);
    Task<IEnumerable<Product>> GetProductsByPriceRangeAsync(decimal minPrice, decimal maxPrice);
    Task<IEnumerable<Product>> GetCloverLinkedProductsAsync();
}

public class ProductService : CosmosDbServiceBase<Product>, IProductService
{
    public ProductService(
        CosmosClient cosmosClient,
        IConfiguration configuration,
        IUserContextAccessor userContextAccessor)
        : base(
            cosmosClient,
            configuration["CosmosDb:DatabaseName"],
            configuration["CosmosDb:ProductsContainerName"],
            userContextAccessor)
    {
    }

    // Override to add product-specific validation
    protected override void OnBeforeCreate(Product item)
    {
        base.OnBeforeCreate(item);

        // Custom validation
        if (item.Price < 0)
        {
            throw new ValidationException("Price cannot be negative");
        }

        // Auto-generate SKU if not provided
        if (string.IsNullOrEmpty(item.Sku))
        {
            item.Sku = $"SKU-{Guid.NewGuid().ToString().Substring(0, 8).ToUpper()}";
        }
    }

    public async Task<bool> UpdateIsCloverLinkedAsync(string id, bool isCloverLinked)
    {
        var fieldsToUpdate = new Dictionary<string, object>
        {
            { "isCloverLinked", isCloverLinked }
        };

        return await PatchFieldsAsync(id, fieldsToUpdate);
    }

    public async Task<IEnumerable<Product>> GetProductsByPriceRangeAsync(decimal minPrice, decimal maxPrice)
    {
        var userContext = GetUserContext();

        var query = new QueryDefinition(
            "SELECT * FROM c WHERE c.sponsorId = @sponsorId " +
            "AND c.subscriberId = @subscriberId " +
            "AND c.price >= @minPrice AND c.price <= @maxPrice")
            .WithParameter("@sponsorId", userContext.SponsorId)
            .WithParameter("@subscriberId", userContext.SubscriberId)
            .WithParameter("@minPrice", minPrice)
            .WithParameter("@maxPrice", maxPrice);

        return await QueryAsync(query);
    }

    public async Task<IEnumerable<Product>> GetCloverLinkedProductsAsync()
    {
        return await GetAllAsync("c.isCloverLinked = true");
    }
}



