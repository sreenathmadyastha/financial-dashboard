public abstract class SnowflakeRepositoryBase
{
    protected readonly ISnowflakeConnectionFactory ConnectionFactory;
    protected readonly IUserContext UserContext;
    protected readonly IKeyVaultAccess KeyVaultAccess;

    protected SnowflakeRepositoryBase(
        ISnowflakeConnectionFactory connectionFactory,
        IUserContext userContext,
        IKeyVaultAccess keyVaultAccess)
    {
        ConnectionFactory = connectionFactory;
        UserContext = userContext;
        KeyVaultAccess = keyVaultAccess;
    }

    protected async Task<T?> QuerySingleOrDefaultAsync<T>(
        string sql,
        object? parameters = null,
        CancellationToken ct = default)
    {
        using var connection = await ConnectionFactory.CreateOpenAsync(ct);
        return await connection.QuerySingleOrDefaultAsync<T>(sql, parameters);
    }

    protected async Task<IEnumerable<T>> QueryAsync<T>(
        string sql,
        object? parameters = null,
        CancellationToken ct = default)
    {
        using var connection = await ConnectionFactory.CreateOpenAsync(ct);
        return await connection.QueryAsync<T>(sql, parameters);
    }

    protected async Task<T> QueryFirstAsync<T>(
        string sql,
        object? parameters = null,
        CancellationToken ct = default)
    {
        using var connection = await ConnectionFactory.CreateOpenAsync(ct);
        return await connection.QueryFirstAsync<T>(sql, parameters);
    }

    protected async Task<int> ExecuteAsync(
        string sql,
        object? parameters = null,
        CancellationToken ct = default)
    {
        using var connection = await ConnectionFactory.CreateOpenAsync(ct);
        return await connection.ExecuteAsync(sql, parameters);
    }

    protected async Task<T?> ExecuteScalarAsync<T>(
        string sql,
        object? parameters = null,
        CancellationToken ct = default)
    {
        using var connection = await ConnectionFactory.CreateOpenAsync(ct);
        return await connection.ExecuteScalarAsync<T>(sql, parameters);
    }
}