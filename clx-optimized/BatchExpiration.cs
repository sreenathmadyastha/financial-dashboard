// Option 3: Batch Expiration with Request-Level TTL
// Set all data retrieved in a single request to expire at the same time:
public class ClxDataService : IClxDataService
{
    public async Task<TransactionSummaryResponse> GetDataAsync(
        DateTime fromDate,
        DateTime toDate,
        CancellationToken ct = default)
    {
        // ... existing code to fetch data ...

        // After combining cached + fetched data, align ALL expirations
        if (uncachedRanges.Any())
        {
            var fetchedResults = await Task.WhenAll(fetchTasks);

            // Calculate unified expiration time for this request
            var unifiedExpiration = TimeSpan.FromHours(4);

            // Save newly fetched data to Redis
            var toCache = fetchedResults.ToDictionary(r => r.CacheKey, r => r.Data);
            await _cache.SetManyAsync(toCache, unifiedExpiration, ct);

            // ALSO refresh expiration on previously cached data
            var existingCacheKeys = monthlyResponses.Keys
                .Select(mk => cacheKeys[Array.IndexOf(monthlyRanges.Select(GetMonthKey).ToArray(), mk)])
                .ToList();

            if (existingCacheKeys.Any())
            {
                await _cache.RefreshExpirationAsync(existingCacheKeys, unifiedExpiration, ct);
                _logger.LogInformation("Aligned {Count} existing cache entries to new expiration",
                    existingCacheKeys.Count);
            }
        }

        return AggregateResults(monthlyResponses);
    }
}

// Add to ClxRedisCache
// public async Task RefreshExpirationAsync(
//     IEnumerable<string> keys,
//     TimeSpan expiration,
//     CancellationToken ct = default)
// {
//     var batch = _db.CreateBatch();
//     var tasks = keys.Select(key => batch.KeyExpireAsync(key, expiration)).ToList();
//     batch.Execute();
//     await Task.WhenAll(tasks);
// }