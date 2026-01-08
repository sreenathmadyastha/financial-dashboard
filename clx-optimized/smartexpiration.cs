// Option 2: Smart Expiration Check Before Returning Data
// Check TTL before using cached data and refetch if expiring soon:

public class ClxDataService : IClxDataService
{
    private readonly TimeSpan _minimumRemainingTtl = TimeSpan.FromMinutes(30);

    public async Task<TransactionSummaryResponse> GetDataAsync(
        DateTime fromDate,
        DateTime toDate,
        CancellationToken ct = default)
    {
        var monthlyRanges = SplitIntoMonths(fromDate, toDate);
        var cacheKeys = monthlyRanges.Select(r => GenerateCacheKey(r.Start, r.End)).ToList();

        // Batch get from Redis WITH TTL check
        var cachedData = await _cache.GetManyAsync<ClxApiResponse>(cacheKeys, ct);
        var ttls = await _cache.GetTtlsAsync(cacheKeys, ct);

        var monthlyResponses = new Dictionary<string, ClxApiResponse>();
        var uncachedRanges = new List<(DateTime Start, DateTime End, string CacheKey, string MonthKey)>();

        for (int i = 0; i < monthlyRanges.Count; i++)
        {
            var range = monthlyRanges[i];
            var cacheKey = cacheKeys[i];
            var monthKey = GetMonthKey(range.Start);
            var ttl = ttls[cacheKey];

            // Use cache only if data exists AND has sufficient TTL remaining
            if (cachedData[cacheKey] != null &&
                ttl.HasValue &&
                ttl.Value > _minimumRemainingTtl)
            {
                _logger.LogDebug("Cache HIT with {Minutes}min remaining for {CacheKey}",
                    ttl.Value.TotalMinutes, cacheKey);
                monthlyResponses[monthKey] = cachedData[cacheKey]!;
            }
            else
            {
                if (cachedData[cacheKey] != null)
                {
                    _logger.LogDebug("Cache entry expiring soon ({Minutes}min), refetching {CacheKey}",
                        ttl?.TotalMinutes ?? 0, cacheKey);
                }
                uncachedRanges.Add((range.Start, range.End, cacheKey, monthKey));
            }
        }

        // Continue with fetching uncached ranges...
    }
}

// Add to IClxRedisCache interface
public interface IClxRedisCache
{
    Task<Dictionary<string, TimeSpan?>> GetTtlsAsync(IEnumerable<string> keys, CancellationToken ct = default);
}

// Implementation
// public async Task<Dictionary<string, TimeSpan?>> GetTtlsAsync(IEnumerable<string> keys, CancellationToken ct = default)
// {
//     var redisKeys = keys.Select(k => (RedisKey)k).ToArray();
//     var tasks = redisKeys.Select(k => _db.KeyTimeToLiveAsync(k)).ToList();
//     var ttls = await Task.WhenAll(tasks);

//     return redisKeys
//         .Select((key, index) => new { Key = key.ToString(), Ttl = ttls[index] })
//         .ToDictionary(x => x.Key, x => x.Ttl);
// }