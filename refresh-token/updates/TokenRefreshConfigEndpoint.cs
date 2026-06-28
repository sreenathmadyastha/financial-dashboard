using FastEndpoints;
using Insights.Auth.Models;
using Insights.Auth.Services;
using Microsoft.Extensions.Configuration;

namespace Insights.Auth.Endpoints;

/// <summary>
/// GET /auth/token-refresh-config
///
/// Returns the full token parameter set for any UI that needs to re-fetch config
/// (e.g. after a page reload, or a second micro-frontend mounting later).
///
/// Reads TokenExpirationSeconds from the cached CorporateTokenService — no second
/// outbound call to the corporate API. The exchange endpoint already populated the cache.
/// </summary>
public class TokenRefreshConfigEndpoint : EndpointWithoutRequest<TokenRefreshConfig>
{
    private readonly IConfiguration _config;
    private readonly ICorporateTokenService _corporateTokenService;

    public TokenRefreshConfigEndpoint(
        IConfiguration config,
        ICorporateTokenService corporateTokenService)
    {
        _config = config;
        _corporateTokenService = corporateTokenService;
    }

    public override void Configure()
    {
        Get("/auth/token-refresh-config");
        AllowAnonymous();
        Description(b => b
            .WithTags("Auth")
            .WithSummary("Returns token parameters for UI refresh scheduling — no corporate API call"));
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        // Reads from cache — does not call the corporate token API again.
        var corporateToken = await _corporateTokenService.GetCachedAsync(ct);
        var section = _config.GetSection("Auth:TokenRefresh");

        await SendOkAsync(new TokenRefreshConfig
        {
            TokenExpirationSeconds = corporateToken.ExpiresInMinutes * 60,
            RefreshBeforeSeconds   = section.GetValue<int>("RefreshBeforeSeconds"),
            HardStopBeforeSeconds  = section.GetValue<int>("HardStopBeforeSeconds"),
            MaxRetries             = section.GetValue<int>("MaxRetries"),
            RetryBackoffMs         = section.GetValue<int>("RetryBackoffMs")
        }, ct);
    }
}
