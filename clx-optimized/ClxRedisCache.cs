// Redis Cache Service
public interface IClxRedisCache
{
    Task<T?> GetAsync<T>(string key, CancellationToken ct = default);
    Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken ct = default);
    Task<Dictionary<string, T?>> GetManyAsync<T>(IEnumerable<string> keys, CancellationToken ct = default);
    Task SetManyAsync<T>(Dictionary<string, T> keyValues, TimeSpan? expiration = null, CancellationToken ct = default);
}

public class ClxRedisCache : IClxRedisCache
{
    private readonly IDatabase _db;
    private readonly TimeSpan _defaultExpiration = TimeSpan.FromHours(4);
    private readonly JsonSerializerOptions _jsonOptions;

    public ClxRedisCache(IConnectionMultiplexer redis)
    {
        _db = redis.GetDatabase();
        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };
    }

    public async Task<T?> GetAsync<T>(string key, CancellationToken ct = default)
    {
        var value = await _db.StringGetAsync(key);
        return value.IsNullOrEmpty ? default : JsonSerializer.Deserialize<T>(value!, _jsonOptions);
    }

    public async Task SetAsync<T>(string key, T value, TimeSpan? expiration = null, CancellationToken ct = default)
    {
        var serialized = JsonSerializer.Serialize(value, _jsonOptions);
        await _db.StringSetAsync(key, serialized, expiration ?? _defaultExpiration);
    }

    public async Task<Dictionary<string, T?>> GetManyAsync<T>(IEnumerable<string> keys, CancellationToken ct = default)
    {
        var redisKeys = keys.Select(k => (RedisKey)k).ToArray();
        var values = await _db.StringGetAsync(redisKeys);

        var result = new Dictionary<string, T?>();
        for (int i = 0; i < redisKeys.Length; i++)
        {
            var key = redisKeys[i].ToString();
            result[key] = values[i].IsNullOrEmpty
                ? default
                : JsonSerializer.Deserialize<T>(values[i]!, _jsonOptions);
        }

        return result;
    }

    public async Task SetManyAsync<T>(Dictionary<string, T> keyValues, TimeSpan? expiration = null, CancellationToken ct = default)
    {
        var batch = _db.CreateBatch();
        var tasks = new List<Task>();
        var exp = expiration ?? _defaultExpiration;

        foreach (var kvp in keyValues)
        {
            var serialized = JsonSerializer.Serialize(kvp.Value, _jsonOptions);
            tasks.Add(batch.StringSetAsync(kvp.Key, serialized, exp));
        }

        batch.Execute();
        await Task.WhenAll(tasks);
    }
}