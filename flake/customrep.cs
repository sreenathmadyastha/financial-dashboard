public class CustomerRepository : SnowflakeRepositoryBase, ICustomerRepository
{
    public CustomerRepository(
        ISnowflakeConnectionFactory connectionFactory,
        IUserContext userContext,
        IKeyVaultAccess keyVaultAccess)
        : base(connectionFactory, userContext, keyVaultAccess)
    {
    }

    public async Task<Customer?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        return await QuerySingleOrDefaultAsync<Customer>(Queries.GetById, new { id }, ct);
    }

    public async Task<IEnumerable<Customer>> GetByTenantAsync(CancellationToken ct = default)
    {
        // Use UserContext from base class
        return await QueryAsync<Customer>(
            Queries.GetByTenant,
            new { UserContext.TenantId },
            ct);
    }

    private static class Queries
    {
        public const string GetById = @"
            SELECT customer_id AS Id, name AS Name, email AS Email
            FROM customers
            WHERE customer_id = :id";

        public const string GetByTenant = @"
            SELECT customer_id AS Id, name AS Name, email AS Email
            FROM customers
            WHERE tenant_id = :TenantId";
    }
}