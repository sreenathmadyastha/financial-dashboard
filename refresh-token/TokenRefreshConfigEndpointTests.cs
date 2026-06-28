using FastEndpoints;
using FastEndpoints.Testing;
using Insights.Auth.Endpoints;
using Insights.Auth.Models;
using Microsoft.Extensions.Configuration;
using NSubstitute;
using Xunit;

namespace Insights.Auth.Tests;

public class TokenRefreshConfigEndpointTests
{
    private static IConfiguration BuildConfig(
        int refreshBefore = 60,
        int hardStop = 20,
        int maxRetries = 3,
        int backoffMs = 2000)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Auth:TokenRefresh:RefreshBeforeSeconds"] = refreshBefore.ToString(),
            ["Auth:TokenRefresh:HardStopBeforeSeconds"] = hardStop.ToString(),
            ["Auth:TokenRefresh:MaxRetries"] = maxRetries.ToString(),
            ["Auth:TokenRefresh:RetryBackoffMs"] = backoffMs.ToString(),
        };

        return new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();
    }

    [Fact]
    public async Task Returns_DefaultConfig_Values()
    {
        // Arrange
        var config = BuildConfig();
        var ep = Factory.Create<TokenRefreshConfigEndpoint>(config);

        // Act
        await ep.HandleAsync(CancellationToken.None);
        var response = ep.Response;

        // Assert
        Assert.Equal(60, response.RefreshBeforeSeconds);
        Assert.Equal(20, response.HardStopBeforeSeconds);
        Assert.Equal(3, response.MaxRetries);
        Assert.Equal(2000, response.RetryBackoffMs);
    }

    [Fact]
    public async Task Returns_CustomConfig_WhenOverridden()
    {
        // Arrange — simulates bumping the window in App Configuration without redeployment
        var config = BuildConfig(refreshBefore: 90, hardStop: 30, maxRetries: 5, backoffMs: 3000);
        var ep = Factory.Create<TokenRefreshConfigEndpoint>(config);

        // Act
        await ep.HandleAsync(CancellationToken.None);
        var response = ep.Response;

        // Assert
        Assert.Equal(90, response.RefreshBeforeSeconds);
        Assert.Equal(30, response.HardStopBeforeSeconds);
        Assert.Equal(5, response.MaxRetries);
        Assert.Equal(3000, response.RetryBackoffMs);
    }

    [Fact]
    public async Task HardStop_IsAlwaysLessThan_RefreshBefore()
    {
        // Invariant: the hard stop window must be narrower than the refresh window.
        // If they're equal or inverted, every first attempt would be immediately aborted.
        var config = BuildConfig(refreshBefore: 60, hardStop: 20);
        var ep = Factory.Create<TokenRefreshConfigEndpoint>(config);

        await ep.HandleAsync(CancellationToken.None);
        var response = ep.Response;

        Assert.True(
            response.HardStopBeforeSeconds < response.RefreshBeforeSeconds,
            $"HardStopBeforeSeconds ({response.HardStopBeforeSeconds}) must be less than " +
            $"RefreshBeforeSeconds ({response.RefreshBeforeSeconds})");
    }

    [Fact]
    public async Task RetryBudget_FitsWithin_RefreshWindow()
    {
        // Verify the total worst-case retry time (sum of all backoff delays)
        // fits inside the window between RefreshBefore and HardStop.
        var config = BuildConfig(refreshBefore: 60, hardStop: 20, maxRetries: 3, backoffMs: 2000);
        var ep = Factory.Create<TokenRefreshConfigEndpoint>(config);

        await ep.HandleAsync(CancellationToken.None);
        var r = ep.Response;

        // Sum of exponential backoff: backoff * (2^0 + 2^1 + ... + 2^(maxRetries-1))
        var totalRetryMs = Enumerable
            .Range(0, r.MaxRetries)
            .Sum(attempt => r.RetryBackoffMs * Math.Pow(2, attempt));

        var availableWindowMs = (r.RefreshBeforeSeconds - r.HardStopBeforeSeconds) * 1000;

        Assert.True(
            totalRetryMs < availableWindowMs,
            $"Total retry budget ({totalRetryMs}ms) must fit inside the available window ({availableWindowMs}ms)");
    }
}
