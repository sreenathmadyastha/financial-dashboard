using FastEndpoints;
using Insights.Auth.Models;
using Microsoft.Extensions.Configuration;

namespace Insights.Auth.Endpoints;

/// <summary>
/// Returns token refresh behavioural config to the UI.
/// The UI uses this to schedule pre-expiry refresh and govern retry logic.
///
/// Values live in appsettings.json / Azure App Configuration under "Auth:TokenRefresh"
/// so they can be tuned without redeployment.
/// </summary>
public class TokenRefreshConfigEndpoint : EndpointWithoutRequest<TokenRefreshConfig>
{
    private readonly IConfiguration _config;

    public TokenRefreshConfigEndpoint(IConfiguration config)
    {
        _config = config;
    }

    public override void Configure()
    {
        Get("/auth/token-refresh-config");
        // Authenticated — UI fetches this after login, so a valid session is expected.
        // Switch to AllowAnonymous() if you need it available before login completes.
        AllowAnonymous();
        Description(b => b
            .WithTags("Auth")
            .WithSummary("Returns token refresh scheduling config for the UI"));
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var section = _config.GetSection("Auth:TokenRefresh");

        var response = new TokenRefreshConfig
        {
            RefreshBeforeSeconds = section.GetValue<int>("RefreshBeforeSeconds"),
            HardStopBeforeSeconds = section.GetValue<int>("HardStopBeforeSeconds"),
            MaxRetries = section.GetValue<int>("MaxRetries"),
            RetryBackoffMs = section.GetValue<int>("RetryBackoffMs")
        };

        await SendOkAsync(response, ct);
    }
}
