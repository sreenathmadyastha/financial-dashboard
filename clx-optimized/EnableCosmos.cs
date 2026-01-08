// Configuration
public class DataPersistenceOptions
{
    public bool EnableCosmosDb { get; set; } = false; // Feature flag
    public bool UseCosmosAsFailover { get; set; } = true; // Only use if Redis fails
    public bool SaveAllToCosmos { get; set; } = false; // Always save to Cosmos
}

// Service Registration
public static class ServiceConfiguration
{
    public static IServiceCollection AddClxServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Redis connection
        services.AddSingleton<IConnectionMultiplexer>(sp =>
            ConnectionMultiplexer.Connect(configuration.GetConnectionString("Redis")));

        services.AddSingleton<IClxRedisCache, ClxRedisCache>();

        // Optional Cosmos DB
        var cosmosOptions = configuration.GetSection("DataPersistence").Get<DataPersistenceOptions>();
        services.AddSingleton(cosmosOptions ?? new DataPersistenceOptions());

        if (cosmosOptions?.EnableCosmosDb == true)
        {
            services.AddSingleton<CosmosClient>(sp =>
            {
                var cosmosConfig = configuration.GetSection("CosmosDb");
                return new CosmosClient(
                    cosmosConfig["ConnectionString"],
                    new CosmosClientOptions
                    {
                        SerializerOptions = new CosmosSerializationOptions
                        {
                            PropertyNamingPolicy = CosmosPropertyNamingPolicy.CamelCase
                        }
                    });
            });
            services.AddSingleton<IClxCosmosRepository, ClxCosmosRepository>();
        }
        else
        {
            // No-op implementation when Cosmos is disabled
            services.AddSingleton<IClxCosmosRepository, NoOpCosmosRepository>();
        }

        services.AddHttpClient<IClxApiClient, ClxApiClient>();
        services.AddScoped<IClxDataService, ClxDataServiceWithCosmos>();

        return services;
    }
}

// Cosmos Repository Interface
public interface IClxCosmosRepository
{
    Task<ClxApiResponse?> GetAsync(DateTime fromDate, DateTime toDate, CancellationToken ct = default);
    Task<List<ClxApiResponse>> GetManyAsync(List<(DateTime, DateTime)> ranges, CancellationToken ct = default);
    Task SaveAsync(DateTime fromDate, DateTime toDate, ClxApiResponse data, CancellationToken ct = default);
    Task SaveManyAsync(Dictionary<(DateTime, DateTime), ClxApiResponse> data, CancellationToken ct = default);
}

// Cosmos Repository Implementation
public class ClxCosmosRepository : IClxCosmosRepository
{
    private readonly Container _container;
    private readonly ILogger<ClxCosmosRepository> _logger;

    public ClxCosmosRepository(CosmosClient cosmosClient, ILogger<ClxCosmosRepository> logger)
    {
        _logger = logger;
        var database = cosmosClient.GetDatabase("ClxData");
        _container = database.GetContainer("Transactions");
    }

    public async Task<ClxApiResponse?> GetAsync(DateTime fromDate, DateTime toDate, CancellationToken ct = default)
    {
        try
        {
            var id = GenerateId(fromDate, toDate);
            var partitionKey = GeneratePartitionKey(fromDate);

            var response = await _container.ReadItemAsync<TransactionDocument>(
                id,
                new PartitionKey(partitionKey),
                cancellationToken: ct);

            return response.Resource?.ToApiResponse();
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading from Cosmos DB");
            return null; // Fail gracefully
        }
    }

    public async Task<List<ClxApiResponse>> GetManyAsync(
        List<(DateTime From, DateTime To)> ranges,
        CancellationToken ct = default)
    {
        var tasks = ranges.Select(r => GetAsync(r.From, r.To, ct));
        var results = await Task.WhenAll(tasks);
        return results.Where(r => r != null).ToList()!;
    }

    public async Task SaveAsync(
        DateTime fromDate,
        DateTime toDate,
        ClxApiResponse data,
        CancellationToken ct = default)
    {
        try
        {
            var document = TransactionDocument.FromApiResponse(fromDate, toDate, data);
            await _container.UpsertItemAsync(
                document,
                new PartitionKey(document.PartitionKey),
                cancellationToken: ct);

            _logger.LogDebug("Saved to Cosmos: {From} to {To}", fromDate, toDate);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving to Cosmos DB");
            // Don't throw - saving to Cosmos is optional
        }
    }

    public async Task SaveManyAsync(
        Dictionary<(DateTime From, DateTime To), ClxApiResponse> data,
        CancellationToken ct = default)
    {
        var tasks = data.Select(kvp => SaveAsync(kvp.Key.From, kvp.Key.To, kvp.Value, ct));
        await Task.WhenAll(tasks);
    }

    private string GenerateId(DateTime from, DateTime to)
    {
        return $"{from:yyyyMM}_{to:yyyyMM}";
    }

    private string GeneratePartitionKey(DateTime date)
    {
        return date.ToString("yyyy"); // Partition by year
    }
}

// No-op implementation when Cosmos is disabled
public class NoOpCosmosRepository : IClxCosmosRepository
{
    public Task<ClxApiResponse?> GetAsync(DateTime fromDate, DateTime toDate, CancellationToken ct = default)
        => Task.FromResult<ClxApiResponse?>(null);

    public Task<List<ClxApiResponse>> GetManyAsync(List<(DateTime, DateTime)> ranges, CancellationToken ct = default)
        => Task.FromResult(new List<ClxApiResponse>());

    public Task SaveAsync(DateTime fromDate, DateTime toDate, ClxApiResponse data, CancellationToken ct = default)
        => Task.CompletedTask;

    public Task SaveManyAsync(Dictionary<(DateTime, DateTime), ClxApiResponse> data, CancellationToken ct = default)
        => Task.CompletedTask;
}

// Cosmos Document Model
public class TransactionDocument
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    public string PartitionKey { get; set; } = string.Empty;
    public DateTime FromDate { get; set; }
    public DateTime ToDate { get; set; }
    public decimal SettledTransactions { get; set; }
    public decimal AuthorizedTransactions { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public int Ttl { get; set; } = -1; // -1 means no expiration, or set to seconds for auto-delete

    public static TransactionDocument FromApiResponse(
        DateTime from,
        DateTime to,
        ClxApiResponse response)
    {
        return new TransactionDocument
        {
            Id = $"{from:yyyyMM}_{to:yyyyMM}",
            PartitionKey = from.ToString("yyyy"),
            FromDate = from,
            ToDate = to,
            SettledTransactions = response.SettledTransactions,
            AuthorizedTransactions = response.AuthorizedTransactions,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
    }

    public ClxApiResponse ToApiResponse()
    {
        return new ClxApiResponse
        {
            SettledTransactions = SettledTransactions,
            AuthorizedTransactions = AuthorizedTransactions
        };
    }
}

// Enhanced Data Service with Optional Cosmos DB
public class ClxDataServiceWithCosmos : IClxDataService
{
    private readonly IClxRedisCache _cache;
    private readonly IClxCosmosRepository _cosmosRepo;
    private readonly IClxApiClient _apiClient;
    private readonly DataPersistenceOptions _options;
    private readonly ILogger<ClxDataServiceWithCosmos> _logger;
    private const string CacheKeyPrefix = "CLX_DATA";

    public ClxDataServiceWithCosmos(
        IClxRedisCache cache,
        IClxCosmosRepository cosmosRepo,
        IClxApiClient apiClient,
        DataPersistenceOptions options,
        ILogger<ClxDataServiceWithCosmos> logger)
    {
        _cache = cache;
        _cosmosRepo = cosmosRepo;
        _apiClient = apiClient;
        _options = options;
        _logger = logger;
    }

    public async Task<TransactionSummaryResponse> GetDataAsync(
        DateTime fromDate,
        DateTime toDate,
        CancellationToken ct = default)
    {
        var monthlyRanges = SplitIntoMonths(fromDate, toDate);
        var cacheKeys = monthlyRanges.Select(r => GenerateCacheKey(r.Start, r.End)).ToList();

        // Step 1: Try Redis cache
        var cachedData = await TryGetFromRedis(cacheKeys, ct);

        var monthlyResponses = new Dictionary<string, ClxApiResponse>();
        var uncachedRanges = new List<(DateTime Start, DateTime End, string CacheKey, string MonthKey)>();

        for (int i = 0; i < monthlyRanges.Count; i++)
        {
            var range = monthlyRanges[i];
            var cacheKey = cacheKeys[i];
            var monthKey = GetMonthKey(range.Start);

            if (cachedData.ContainsKey(cacheKey) && cachedData[cacheKey] != null)
            {
                _logger.LogDebug("Redis cache HIT for {CacheKey}", cacheKey);
                monthlyResponses[monthKey] = cachedData[cacheKey]!;
            }
            else
            {
                _logger.LogDebug("Redis cache MISS for {CacheKey}", cacheKey);
                uncachedRanges.Add((range.Start, range.End, cacheKey, monthKey));
            }
        }

        // Step 2: If enabled, try Cosmos DB for Redis misses
        if (_options.EnableCosmosDb && _options.UseCosmosAsFailover && uncachedRanges.Any())
        {
            var cosmosRanges = uncachedRanges.Select(r => (r.Start, r.End)).ToList();
            var cosmosData = await _cosmosRepo.GetManyAsync(cosmosRanges, ct);

            var cosmosDict = cosmosData
                .Zip(uncachedRanges, (data, range) => new { Data = data, Range = range })
                .Where(x => x.Data != null)
                .ToDictionary(x => x.Range.MonthKey, x => x.Data);

            foreach (var kvp in cosmosDict)
            {
                _logger.LogInformation("Cosmos DB FOUND data for {MonthKey}", kvp.Key);
                monthlyResponses[kvp.Key] = kvp.Value;

                // Update uncached ranges to exclude this one
                uncachedRanges.RemoveAll(r => r.MonthKey == kvp.Key);

                // Backfill Redis cache
                var range = uncachedRanges.FirstOrDefault(r => r.MonthKey == kvp.Key);
                if (!string.IsNullOrEmpty(range.CacheKey))
                {
                    await _cache.SetAsync(range.CacheKey, kvp.Value, ct: ct);
                }
            }
        }

        // Step 3: Fetch remaining data from CLX API
        if (uncachedRanges.Any())
        {
            var fetchTasks = uncachedRanges.Select(async range =>
            {
                var data = await _apiClient.FetchDataAsync(range.Start, range.End, ct);
                return (Data: data, range.Start, range.End, range.CacheKey, range.MonthKey);
            });

            var fetchedResults = await Task.WhenAll(fetchTasks);

            // Save to Redis
            var toCache = fetchedResults.ToDictionary(r => r.CacheKey, r => r.Data);
            await _cache.SetManyAsync(toCache, cancellationToken: ct);

            // Optionally save to Cosmos DB
            if (_options.EnableCosmosDb && _options.SaveAllToCosmos)
            {
                var toCosmos = fetchedResults.ToDictionary(
                    r => (r.Start, r.End),
                    r => r.Data);
                await _cosmosRepo.SaveManyAsync(toCosmos, ct);
                _logger.LogInformation("Saved {Count} ranges to Cosmos DB", fetchedResults.Length);
            }

            // Add to monthly responses
            foreach (var result in fetchedResults)
            {
                monthlyResponses[result.MonthKey] = result.Data;
            }

            _logger.LogInformation("Fetched {Count} ranges from CLX API", uncachedRanges.Count);
        }

        return AggregateResults(monthlyResponses);
    }

    private async Task<Dictionary<string, ClxApiResponse?>> TryGetFromRedis(
        List<string> keys,
        CancellationToken ct)
    {
        try
        {
            return await _cache.GetManyAsync<ClxApiResponse>(keys, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Redis failure, returning empty cache result");
            return keys.ToDictionary(k => k, k => (ClxApiResponse?)null);
        }
    }

    private List<(DateTime Start, DateTime End)> SplitIntoMonths(DateTime fromDate, DateTime toDate)
    {
        var ranges = new List<(DateTime Start, DateTime End)>();
        var current = new DateTime(fromDate.Year, fromDate.Month, 1);
        var end = toDate;

        while (current <= end)
        {
            var monthEnd = new DateTime(current.Year, current.Month,
                DateTime.DaysInMonth(current.Year, current.Month));
            var rangeEnd = monthEnd > end ? end : monthEnd;

            ranges.Add((current, rangeEnd));
            current = monthEnd.AddDays(1);
        }

        return ranges;
    }

    private string GenerateCacheKey(DateTime start, DateTime end)
    {
        return $"{CacheKeyPrefix}:{start:yyyyMM}:{end:yyyyMM}";
    }

    private string GetMonthKey(DateTime date)
    {
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
            var monthLabel = $"Month{month.Index}";
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

/* Configuration Example - appsettings.json

{
  "ConnectionStrings": {
    "Redis": "localhost:6379,abortConnect=false"
  },
  "CosmosDb": {
    "ConnectionString": "AccountEndpoint=https://...;AccountKey=..."
  },
  "DataPersistence": {
    "EnableCosmosDb": false,           // Set to true to enable Cosmos DB
    "UseCosmosAsFailover": true,       // Only query Cosmos if Redis fails
    "SaveAllToCosmos": false           // Always save fetched data to Cosmos
  }
}

Recommended Settings:
1. Dev/Test: EnableCosmosDb = false (use Redis only)
2. Production (cost-conscious): EnableCosmosDb = true, UseCosmosAsFailover = true, SaveAllToCosmos = false
3. Production (compliance/audit): EnableCosmosDb = true, UseCosmosAsFailover = true, SaveAllToCosmos = true
*/