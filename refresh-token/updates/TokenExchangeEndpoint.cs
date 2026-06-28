using FastEndpoints;
using Insights.Auth.Models;
using Insights.Auth.Services;
using Microsoft.Extensions.Configuration;

namespace Insights.Auth.Endpoints;

/// <summary>
/// POST /api/token-exchange
///
/// Converts a product token into an API token by calling the corporate token API.
/// Returns the API token alongside all refresh scheduling parameters so the UI
/// has everything it needs in a single call — no separate config fetch required at startup.
///
/// The corporate token API's ExpiresIn (minutes) is converted to seconds here.
/// The same metadata is cached internally and served by /auth/token-refresh-config
/// and the refresh endpoint without any further outbound calls.
/// </summary>
public class TokenExchangeEndpoint : Endpoint<TokenExchangeRequest, TokenExchangeResponse>
{
    private readonly ICorporateTokenService _corporateTokenService;
    private readonly IConfiguration _config;

    public TokenExchangeEndpoint(
        ICorporateTokenService corporateTokenService,
        IConfiguration config)
    {
        _corporateTokenService = corporateTokenService;
        _config = config;
    }

    public override void Configure()
    {
        Post("/api/token-exchange");
        AllowAnonymous();
        Description(b => b
            .WithTags("Auth")
            .WithSummary("Exchanges a product token for an API token with full refresh config"));
    }

    public override async Task HandleAsync(TokenExchangeRequest req, CancellationToken ct)
    {
        // Call the corporate token API — result is cached inside the service.
        var corporateToken = await _corporateTokenService.ExchangeAsync(req.ProductToken, ct);

        // Convert minutes → seconds once here. All downstream code (config endpoint,
        // refresh endpoint, UI) works in seconds from this point.
        var tokenExpirationSeconds = corporateToken.ExpiresInMinutes * 60;

        var section = _config.GetSection("Auth:TokenRefresh");

        await SendOkAsync(new TokenExchangeResponse
        {
            ApiToken               = corporateToken.AccessToken,
            TokenExpirationSeconds = tokenExpirationSeconds,
            RefreshBeforeSeconds   = section.GetValue<int>("RefreshBeforeSeconds"),
            HardStopBeforeSeconds  = section.GetValue<int>("HardStopBeforeSeconds"),
            MaxRetries             = section.GetValue<int>("MaxRetries"),
            RetryBackoffMs         = section.GetValue<int>("RetryBackoffMs")
        }, ct);
    }
}
