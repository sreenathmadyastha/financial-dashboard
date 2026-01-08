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