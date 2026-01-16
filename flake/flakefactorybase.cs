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
        Action<SnowflakeDbCommand>? configureCommand = null,
        CancellationToken ct = default) where T : class, new()
    {
        using var connection = ConnectionFactory.Create();
        await connection.OpenAsync(ct);

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        configureCommand?.Invoke((SnowflakeDbCommand)command);

        using var reader = await command.ExecuteReaderAsync(ct);

        if (await reader.ReadAsync(ct))
            return MapToEntity<T>(reader);

        return null;
    }

    protected async Task<List<T>> QueryAsync<T>(
        string sql,
        Action<SnowflakeDbCommand>? configureCommand = null,
        CancellationToken ct = default) where T : class, new()
    {
        using var connection = ConnectionFactory.Create();
        await connection.OpenAsync(ct);

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        configureCommand?.Invoke((SnowflakeDbCommand)command);

        using var reader = await command.ExecuteReaderAsync(ct);

        var results = new List<T>();
        while (await reader.ReadAsync(ct))
        {
            results.Add(MapToEntity<T>(reader));
        }

        return results;
    }

    protected async Task<int> ExecuteAsync(
        string sql,
        Action<SnowflakeDbCommand>? configureCommand = null,
        CancellationToken ct = default)
    {
        using var connection = ConnectionFactory.Create();
        await connection.OpenAsync(ct);

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        configureCommand?.Invoke((SnowflakeDbCommand)command);

        return await command.ExecuteNonQueryAsync(ct);
    }

    protected async Task<T?> ExecuteScalarAsync<T>(
        string sql,
        Action<SnowflakeDbCommand>? configureCommand = null,
        CancellationToken ct = default)
    {
        using var connection = ConnectionFactory.Create();
        await connection.OpenAsync(ct);

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        configureCommand?.Invoke((SnowflakeDbCommand)command);

        var result = await command.ExecuteScalarAsync(ct);

        if (result is null or DBNull)
            return default;

        return (T)Convert.ChangeType(result, typeof(T));
    }

    private static T MapToEntity<T>(DbDataReader reader) where T : class, new()
    {
        var entity = new T();
        var properties = typeof(T).GetProperties();

        for (var i = 0; i < reader.FieldCount; i++)
        {
            var columnName = reader.GetName(i);
            var property = properties.FirstOrDefault(p =>
                p.Name.Equals(columnName, StringComparison.OrdinalIgnoreCase));

            if (property is null || reader.IsDBNull(i))
                continue;

            var value = reader.GetValue(i);
            property.SetValue(entity, Convert.ChangeType(value, property.PropertyType));
        }

        return entity;
    }
}