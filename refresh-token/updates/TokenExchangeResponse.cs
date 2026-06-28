namespace Insights.Auth.Models;

/// <summary>
/// Response from POST /api/token-exchange.
///
/// Returns the API token plus all scheduling parameters the UI needs
/// to manage refresh without any further config calls at startup.
/// TokenExpirationSeconds is derived from the corporate API's ExpiresIn (minutes)
/// and expressed in seconds here so the UI works in one consistent unit.
/// </summary>
public record TokenExchangeResponse
{
    /// <summary>The API-scoped token to use for all subsequent requests.</summary>
    public string ApiToken { get; init; } = string.Empty;

    /// <summary>
    /// Token lifetime in seconds, converted from the corporate API's ExpiresIn (minutes).
    /// Use as a scheduling baseline only — always derive actual expiry from the
    /// token's own exp claim, as the issuer may vary the lifetime per issuance.
    /// </summary>
    public int TokenExpirationSeconds { get; init; }

    /// <summary>Fire first refresh attempt this many seconds before expiry.</summary>
    public int RefreshBeforeSeconds { get; init; }

    /// <summary>Abort retries below this many seconds remaining on the token.</summary>
    public int HardStopBeforeSeconds { get; init; }

    /// <summary>Maximum refresh attempts before forcing re-authentication.</summary>
    public int MaxRetries { get; init; }

    /// <summary>
    /// Base backoff delay in ms between retries (exponential: base * 2^attempt).
    /// </summary>
    public int RetryBackoffMs { get; init; }
}
