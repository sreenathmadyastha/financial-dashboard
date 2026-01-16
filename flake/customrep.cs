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
        return await QuerySingleOrDefaultAsync<Customer>(
            Queries.GetById,
            cmd => cmd.Parameters.Add(new SnowflakeDbParameter("id", id, DbType.Int32)),
            ct);
    }

    public async Task<List<Customer>> GetByTenantAsync(CancellationToken ct = default)
    {
        return await QueryAsync<Customer>(
            Queries.GetByTenant,
            cmd => cmd.Parameters.Add(new SnowflakeDbParameter("tenantId", UserContext.TenantId, DbType.String)),
            ct);
    }

    public async Task<int> CreateAsync(Customer customer, CancellationToken ct = default)
    {
        return await ExecuteScalarAsync<int>(
            Queries.Create,
            cmd =>
            {
                cmd.Parameters.Add(new SnowflakeDbParameter("name", customer.Name, DbType.String));
                cmd.Parameters.Add(new SnowflakeDbParameter("email", customer.Email, DbType.String));
                cmd.Parameters.Add(new SnowflakeDbParameter("tenantId", UserContext.TenantId, DbType.String));
            },
            ct) ?? 0;
    }

    private static class Queries
    {
        public const string GetById = @"
            SELECT customer_id, name, email
            FROM customers
            WHERE customer_id = :id";

        public const string GetByTenant = @"
            SELECT customer_id, name, email
            FROM customers
            WHERE tenant_id = :tenantId";

        public const string Create = @"
            INSERT INTO customers (name, email, tenant_id)
            VALUES (:name, :email, :tenantId)
            RETURNING customer_id";
    }
}