// Main Data Service with Optimized Caching
public interface IClxDataService
{
    Task<TransactionSummaryResponse> GetDataAsync(DateTime fromDate, DateTime toDate, CancellationToken ct = default);
}

public class ClxDataService : IClxDataService
{
    private readonly IClxRedisCache _cache;
    private readonly IClxApiClient _apiClient;
    private readonly ILogger<ClxDataService> _logger;
    private const string CacheKeyPrefix = "CLX_DATA";

    public ClxDataService(
        IClxRedisCache cache,
        IClxApiClient apiClient,
        ILogger<ClxDataService> logger)
    {
        _cache = cache;
        _apiClient = apiClient;
        _logger = logger;
    }

    public async Task<TransactionSummaryResponse> GetDataAsync(DateTime fromDate, DateTime toDate, CancellationToken ct = default)
    {
        // Split into monthly ranges
        var monthlyRanges = SplitIntoMonths(fromDate, toDate);

        // Generate cache keys for all ranges
        var cacheKeys = monthlyRanges.Select(r => GenerateCacheKey(r.Start, r.End)).ToList();

        // Batch get from Redis
        var cachedData = await _cache.GetManyAsync<ClxApiResponse>(cacheKeys, ct);

        // Identify uncached ranges
        var monthlyResponses = new Dictionary<string, ClxApiResponse>();
        var uncachedRanges = new List<(DateTime Start, DateTime End, string CacheKey, string MonthKey)>();

        for (int i = 0; i < monthlyRanges.Count; i++)
        {
            var range = monthlyRanges[i];
            var cacheKey = cacheKeys[i];
            var monthKey = GetMonthKey(range.Start);

            if (cachedData[cacheKey] != null)
            {
                _logger.LogDebug("Cache HIT for {CacheKey}", cacheKey);
                monthlyResponses[monthKey] = cachedData[cacheKey]!;
            }
            else
            {
                _logger.LogDebug("Cache MISS for {CacheKey}", cacheKey);
                uncachedRanges.Add((range.Start, range.End, cacheKey, monthKey));
            }
        }

        // Fetch uncached data in parallel
        if (uncachedRanges.Any())
        {
            var fetchTasks = uncachedRanges.Select(async range =>
            {
                var data = await _apiClient.FetchDataAsync(range.Start, range.End, ct);
                return (Data: data, CacheKey: range.CacheKey, MonthKey: range.MonthKey);
            });

            var fetchedResults = await Task.WhenAll(fetchTasks);

            // Batch write to Redis
            var toCache = fetchedResults.ToDictionary(r => r.CacheKey, r => r.Data);
            await _cache.SetManyAsync(toCache, cancellationToken: ct);

            // Add to monthly responses
            foreach (var result in fetchedResults)
            {
                monthlyResponses[result.MonthKey] = result.Data;
            }

            _logger.LogInformation("Fetched {Count} ranges from CLX API", uncachedRanges.Count);
        }

        // Combine and return aggregated response
        return AggregateResults(monthlyResponses);
    }

    private List<(DateTime Start, DateTime End)> SplitIntoMonths(DateTime fromDate, DateTime toDate)
    {
        var ranges = new List<(DateTime Start, DateTime End)>();
        var current = new DateTime(fromDate.Year, fromDate.Month, 1); // Start of month
        var end = toDate;

        while (current <= end)
        {
            var monthEnd = new DateTime(current.Year, current.Month, DateTime.DaysInMonth(current.Year, current.Month));
            var rangeEnd = monthEnd > end ? end : monthEnd;

            ranges.Add((current, rangeEnd));
            current = monthEnd.AddDays(1);
        }

        return ranges;
    }

    private string GenerateCacheKey(DateTime start, DateTime end)
    {
        // Format: CLX_DATA:YYYYMM:YYYYMM
        return $"{CacheKeyPrefix}:{start:yyyyMM}:{end:yyyyMM}";
    }

    private string GetMonthKey(DateTime date)
    {
        // Format: "Month1", "Month2", etc. based on chronological order
        // Or use format like "2024-01" for actual month/year
        return date.ToString("yyyy-MM");
    }

    private TransactionSummaryResponse AggregateResults(Dictionary<string, ClxApiResponse> monthlyData)
    {
        var response = new TransactionSummaryResponse
        {
            TotalSettledTransactions = monthlyData.Values.Sum(m => m.SettledTransactions),
            TotalAuthorizedTransactions = monthlyData.Values.Sum(m => m.AuthorizedTransactions),
            MonthlyBreakdown = new Dictionary<string, MonthlyTransactions>()
        };

        // Sort months chronologically
        var sortedMonths = monthlyData
            .OrderBy(kvp => kvp.Key)
            .Select((kvp, index) => new
            {
                Index = index + 1,
                MonthKey = kvp.Key,
                Data = kvp.Value
            });

        foreach (var month in sortedMonths)
        {
            var monthLabel = $"Month{month.Index}"; // Or use month.MonthKey for "2024-01" format
            response.MonthlyBreakdown[monthLabel] = new MonthlyTransactions
            {
                MonthYear = month.MonthKey,
                SettledTransactions = month.Data.SettledTransactions,
                AuthorizedTransactions = month.Data.AuthorizedTransactions
            };
        }

        return response;
    }
}