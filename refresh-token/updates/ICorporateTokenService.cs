namespace Insights.Auth.Services;

/// <summary>
/// The full response shape returned by the corporate token API.
/// ExpiresIn is in minutes, exactly as the issuer returns it.
/// </summary>
public record CorporateTokenResponse
{
    /// <summary>API-scoped token issued by the corporate token API.</summary>
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>
    /// Token lifetime in minutes, as returned by the corporate token API's ExpiresIn field.
    /// </summary>
    public int ExpiresInMinutes { get; init; }
}

/// <summary>
/// Abstraction over the corporate token API.
///
/// Lifecycle contract:
///   - ExchangeAsync  is called by /api/token-exchange. It calls the corporate API,
///                    stores the result internally, and returns it.
///   - GetCachedAsync is called by /auth/token-refresh-config and /api/refresh.
///                    It returns the stored result without any outbound call.
///                    Throws InvalidOperationException if called before ExchangeAsync.
///
/// This design ensures the corporate token API is called exactly once per
/// token lifecycle — at exchange time — not on every config or refresh request.
/// </summary>
public interface ICorporateTokenService
{
    /// <summary>
    /// Exchanges a product token for an API token via the corporate token API.
    /// Stores the response internally so subsequent callers can use GetCachedAsync.
    /// </summary>
    Task<CorporateTokenResponse> ExchangeAsync(string productToken, CancellationToken ct = default);

    /// <summary>
    /// Returns the token metadata stored by the most recent ExchangeAsync call.
    /// Does not make any outbound call.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if called before ExchangeAsync has completed successfully.
    /// </exception>
    Task<CorporateTokenResponse> GetCachedAsync(CancellationToken ct = default);
}
