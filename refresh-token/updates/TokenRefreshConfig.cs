namespace Insights.Auth.Models;

/// <summary>
/// Single source of truth for all token-related parameters consumed by any UI.
///
/// Properties are grouped by ownership:
///
///   READ-ONLY METADATA  — sourced from the corporate token API at runtime.
///                         Reflects what the issuer actually returns; do not
///                         duplicate these values in your own configuration.
///
///   BEHAVIOURAL KNOBS   — owned by Insights; live in Azure App Configuration
///                         and can be tuned at runtime without redeployment.
///
/// All time values are in seconds. The corporate token API returns ExpiresIn
/// in minutes — that conversion happens in the endpoint so the UI never needs to.
/// </summary>
public record TokenRefreshConfig
{
    // ── Read-only metadata (sourced from corporate token API) ─────────────────

    /// <summary>
    /// Token lifetime in seconds, derived from the corporate token API's ExpiresIn
    /// field (which is in minutes) and converted here for UI consistency.
    ///
    /// Informational — use as a scheduling hint only. The UI must always derive
    /// the actual per-token expiry from the live token's own exp claim, since
    /// the issuer may vary the lifetime at any time without notice.
    /// </summary>
    public int TokenExpirationSeconds { get; init; }

    // ── Behavioural knobs (Insights-owned, Azure App Configuration) ──────────

    /// <summary>
    /// How many seconds before expiry the UI fires the first refresh attempt.
    /// Increase this if you observe the corporate token API responding slowly.
    /// Must be less than TokenExpirationSeconds.
    /// </summary>
    public int RefreshBeforeSeconds { get; init; }

    /// <summary>
    /// Abort all retry attempts if fewer than this many seconds remain on the token.
    /// Acts as a hard safety deadline to avoid a refresh call arriving after expiry.
    /// Accounts for: network RTT + corporate token API latency + token propagation time.
    /// Must be less than RefreshBeforeSeconds.
    /// </summary>
    public int HardStopBeforeSeconds { get; init; }

    /// <summary>
    /// Maximum number of refresh attempts before giving up and forcing re-authentication.
    /// </summary>
    public int MaxRetries { get; init; }

    /// <summary>
    /// Base delay in milliseconds for exponential backoff between retries.
    /// Actual delay per attempt = RetryBackoffMs * 2^attempt
    /// e.g. 2000ms base → 2s, 4s, 8s for attempts 0, 1, 2.
    /// Total worst-case retry budget must fit within (RefreshBefore - HardStop) seconds.
    /// </summary>
    public int RetryBackoffMs { get; init; }
}
