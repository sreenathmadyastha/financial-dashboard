namespace Insights.Auth.Models;

/// <summary>
/// Request body for POST /api/token-exchange.
/// The product token is the short-lived credential issued after initial login,
/// which is exchanged here for an API-scoped token from the corporate token API.
/// </summary>
public record TokenExchangeRequest
{
    /// <summary>The product token received after initial authentication.</summary>
    public string ProductToken { get; init; } = string.Empty;
}
