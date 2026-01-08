// Option 1: Use Sliding Expiration with TTL Refresh (RECOMMENDED)
// Update the cache entry's TTL whenever it's accessed, ensuring all data in a response expires together:




using StackExchange.Redis;
using System.Text.Json;

// Service registration in Program.cs or Startup.cs
public static class ServiceConfiguration
{
    public static IServiceCollection AddClxServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Redis connection
        services.AddSingleton<IConnectionMultiplexer>(sp =>
            ConnectionMultiplexer.Connect(configuration.GetConnectionString("Redis")));

        services.AddSingleton<IClxRedisCache, ClxRedisCache>();
        services.AddHttpClient<IClxApiClient, ClxApiClient>();
        services.AddScoped<IClxDataService, ClxDataService>();

        return services;
    }
}

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
        var keysToRefresh = new List<RedisKey>();

        for (int i = 0; i < redisKeys.Length; i++)
        {
            var key = redisKeys[i].ToString();
            if (!values[i].IsNullOrEmpty)
            {
                result[key] = JsonSerializer.Deserialize<T>(values[i]!, _jsonOptions);
                keysToRefresh.Add(redisKeys[i]);
            }
            else
            {
                result[key] = default;
            }
        }

        // Refresh TTL for all retrieved keys to align expiration
        if (keysToRefresh.Any())
        {
            await RefreshExpirationAsync(keysToRefresh);
        }

        return result;
    }

    private async Task RefreshExpirationAsync(List<RedisKey> keys)
    {
        var batch = _db.CreateBatch();
        var tasks = keys.Select(key => batch.KeyExpireAsync(key, _defaultExpiration)).ToList();
        batch.Execute();
        await Task.WhenAll(tasks);
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

// CLX API Client with Rate Limiting
public interface IClxApiClient
{
    Task<ClxApiResponse> FetchDataAsync(DateTime fromDate, DateTime toDate, CancellationToken ct = default);
}

public class ClxApiClient : IClxApiClient
{
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _rateLimiter;
    private readonly ILogger<ClxApiClient> _logger;
    private const int MaxConcurrentRequests = 5;

    public ClxApiClient(HttpClient httpClient, ILogger<ClxApiClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
        _rateLimiter = new SemaphoreSlim(MaxConcurrentRequests);
    }

    public async Task<ClxApiResponse> FetchDataAsync(DateTime fromDate, DateTime toDate, CancellationToken ct = default)
    {
        await _rateLimiter.WaitAsync(ct);

        try
        {
            var url = $"api/data?from={fromDate:yyyy-MM-dd}&to={toDate:yyyy-MM-dd}";
            _logger.LogInformation("Calling CLX API: {Url}", url);

            var response = await _httpClient.GetAsync(url, ct);
            response.EnsureSuccessStatusCode();

            var data = await response.Content.ReadFromJsonAsync<ClxApiResponse>(cancellationToken: ct);
            return data ?? throw new InvalidOperationException("CLX API returned null data");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling CLX API for range {From} to {To}", fromDate, toDate);
            throw;
        }
        finally
        {
            _rateLimiter.Release();
        }
    }
}

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

// API Controller
[ApiController]
[Route("api/[controller]")]
public class TransactionsController : ControllerBase
{
    private readonly IClxDataService _dataService;
    private readonly ILogger<TransactionsController> _logger;

    public TransactionsController(IClxDataService dataService, ILogger<TransactionsController> logger)
    {
        _dataService = dataService;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<TransactionSummaryResponse>> GetTransactions(
        [FromQuery] DateTime fromDate,
        [FromQuery] DateTime toDate,
        CancellationToken ct)
    {
        try
        {
            // Validate date range
            var monthsDiff = GetMonthDifference(fromDate, toDate);
            if (monthsDiff > 12)
            {
                return BadRequest(new { Error = "Maximum range is 12 months" });
            }

            if (monthsDiff != 1 && monthsDiff != 3 && monthsDiff != 6 && monthsDiff != 12)
            {
                return BadRequest(new { Error = "Only 1, 3, 6, or 12 month ranges are supported" });
            }

            _logger.LogInformation("Fetching transactions from {From} to {To} ({Months} months)",
                fromDate, toDate, monthsDiff);

            var result = await _dataService.GetDataAsync(fromDate, toDate, ct);

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching transaction data");
            return StatusCode(500, new { Error = "Error fetching transaction data" });
        }
    }

    private int GetMonthDifference(DateTime start, DateTime end)
    {
        return ((end.Year - start.Year) * 12) + end.Month - start.Month + 1;
    }
}

// Data Models

// CLX API Response (what comes from the external API)
public class ClxApiResponse
{
    public decimal SettledTransactions { get; set; }
    public decimal AuthorizedTransactions { get; set; }
}

// Monthly Transaction Data
public class MonthlyTransactions
{
    public string MonthYear { get; set; } = string.Empty; // e.g., "2024-01"
    public decimal SettledTransactions { get; set; }
    public decimal AuthorizedTransactions { get; set; }
}

// Final Response to Client
public class TransactionSummaryResponse
{
    public decimal TotalSettledTransactions { get; set; }
    public decimal TotalAuthorizedTransactions { get; set; }
    public Dictionary<string, MonthlyTransactions> MonthlyBreakdown { get; set; } = new();
}

/* Example Response:
{
    "totalSettledTransactions": 150000.00,
    "totalAuthorizedTransactions": 175000.00,
    "monthlyBreakdown": {
        "Month1": {
            "monthYear": "2024-01",
            "settledTransactions": 50000.00,
            "authorizedTransactions": 55000.00
        },
        "Month2": {
            "monthYear": "2024-02",
            "settledTransactions": 45000.00,
            "authorizedTransactions": 52000.00
        },
        "Month3": {
            "monthYear": "2024-03",
            "settledTransactions": 55000.00,
            "authorizedTransactions": 68000.00
        }
    }
}
*/