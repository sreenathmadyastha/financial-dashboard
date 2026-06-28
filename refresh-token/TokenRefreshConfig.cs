namespace Insights.Auth.Models;

/// <summary>
/// Configuration returned to the UI to govern token refresh scheduling and retry behaviour.
/// TTL is intentionally excluded — the UI derives it from the token's own exp claim.
/// </summary>
public record TokenRefreshConfig
{
    /// <summary>
    /// How many seconds before expiry the UI fires the first refresh attempt.
    /// Increase this if you observe the corporate token API responding slowly.
    /// </summary>
    public int RefreshBeforeSeconds { get; init; }

    /// <summary>
    /// Abort all retry attempts if fewer than this many seconds remain on the token.
    /// Acts as a hard safety deadline to avoid using a token that expires mid-flight.
    /// </summary>
    public int HardStopBeforeSeconds { get; init; }

    /// <summary>
    /// Maximum number of refresh attempts before giving up and forcing re-authentication.
    /// </summary>
    public int MaxRetries { get; init; }

    /// <summary>
    /// Base delay in milliseconds for exponential backoff between retries.
    /// Actual delay per attempt = RetryBackoffMs * 2^attempt
    /// e.g. 2000ms → 2s, 4s, 8s for attempts 0, 1, 2
    /// </summary>
    public int RetryBackoffMs { get; init; }
}
