using System.Net.Http.Json;

namespace Insights.Auth.Services;

/// <summary>
/// Concrete implementation of ICorporateTokenService.
///
/// Registered as a scoped service so each HTTP request gets its own instance,
/// but the cached token is held for the lifetime of the token itself via IMemoryCache
/// (or your existing Redis/enterprise cache — swap GetCachedAsync accordingly).
///
/// Thread safety: ExchangeAsync uses a SemaphoreSlim to prevent duplicate
/// outbound calls if two requests race at startup.
/// </summary>
public class CorporateTokenService : ICorporateTokenService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<CorporateTokenService> _logger;

    // In a real implementation this would write to / read from your existing
    // enterprise cache (Redis / Azure Cache for Redis) keyed on the sponsor context,
    // consistent with your CachedBrandingProvider and SponsorContextPreProcessor patterns.
    // For simplicity here we use a static field; replace with IMemoryCache or IDistributedCache.
    private static CorporateTokenResponse? _cached;
    private static readonly SemaphoreSlim _lock = new(1, 1);

    public CorporateTokenService(
        HttpClient httpClient,
        ILogger<CorporateTokenService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<CorporateTokenResponse> ExchangeAsync(
        string productToken,
        CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            _logger.LogInformation("Exchanging product token with corporate token API");

            // POST to the corporate token API — adapt the request shape to match
            // your actual corporate API contract (headers, body format, auth, etc.)
            var httpResponse = await _httpClient.PostAsJsonAsync(
                "/token",
                new { product_token = productToken },
                ct);

            httpResponse.EnsureSuccessStatusCode();

            // Map from the corporate API's field names to our internal record.
            // Adjust property names to match the real response shape.
            var raw = await httpResponse.Content.ReadFromJsonAsync<CorporateApiRawResponse>(
                cancellationToken: ct)
                ?? throw new InvalidOperationException("Corporate token API returned empty body");

            _cached = new CorporateTokenResponse
            {
                AccessToken      = raw.AccessToken,
                ExpiresInMinutes = raw.ExpiresIn   // corporate API returns minutes
            };

            _logger.LogInformation(
                "Token exchange successful. ExpiresIn: {Minutes} minutes ({Seconds}s)",
                _cached.ExpiresInMinutes,
                _cached.ExpiresInMinutes * 60);

            return _cached;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc/>
    public Task<CorporateTokenResponse> GetCachedAsync(CancellationToken ct = default)
    {
        if (_cached is null)
            throw new InvalidOperationException(
                "No corporate token available. ExchangeAsync must complete before GetCachedAsync is called.");

        return Task.FromResult(_cached);
    }

    // Raw shape of the corporate API response — internal only, never exposed to callers.
    private record CorporateApiRawResponse
    {
        public string AccessToken { get; init; } = string.Empty;

        // Corporate API returns this as an integer number of minutes.
        public int ExpiresIn { get; init; }
    }
}
