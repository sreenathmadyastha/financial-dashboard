using FastEndpoints;
using FastEndpoints.Testing;
using Insights.Auth.Endpoints;
using Insights.Auth.Models;
using Insights.Auth.Services;
using Microsoft.Extensions.Configuration;
using NSubstitute;
using Xunit;

namespace Insights.Auth.Tests;

public class TokenRefreshConfigEndpointTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static IConfiguration BuildConfig(
        int refreshBefore = 60,
        int hardStop      = 20,
        int maxRetries    = 3,
        int backoffMs     = 2000)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:TokenRefresh:RefreshBeforeSeconds"] = refreshBefore.ToString(),
                ["Auth:TokenRefresh:HardStopBeforeSeconds"] = hardStop.ToString(),
                ["Auth:TokenRefresh:MaxRetries"]            = maxRetries.ToString(),
                ["Auth:TokenRefresh:RetryBackoffMs"]        = backoffMs.ToString(),
            })
            .Build();
    }

    /// <summary>
    /// Mocks GetCachedAsync — the only method the config endpoint should call.
    /// ExchangeAsync is deliberately not set up; any accidental call to it will throw.
    /// </summary>
    private static ICorporateTokenService MockCached(int expiresInMinutes = 10)
    {
        var svc = Substitute.For<ICorporateTokenService>();
        svc.GetCachedAsync(Arg.Any<CancellationToken>())
           .Returns(new CorporateTokenResponse
           {
               AccessToken      = "cached-token",
               ExpiresInMinutes = expiresInMinutes
           });
        return svc;
    }

    private static async Task<TokenRefreshConfig> Execute(
        IConfiguration? config = null,
        ICorporateTokenService? svc = null)
    {
        var ep = Factory.Create<TokenRefreshConfigEndpoint>(
            config ?? BuildConfig(),
            svc    ?? MockCached());
        await ep.HandleAsync(CancellationToken.None);
        return ep.Response;
    }

    // ── TokenExpirationSeconds — from cache, not a new API call ──────────────

    [Theory]
    [InlineData(5,  300)]
    [InlineData(10, 600)]
    [InlineData(15, 900)]
    [InlineData(30, 1800)]
    public async Task TokenExpirationSeconds_ConvertsMinutesToSeconds(
        int expiresInMinutes, int expectedSeconds)
    {
        var response = await Execute(svc: MockCached(expiresInMinutes));
        Assert.Equal(expectedSeconds, response.TokenExpirationSeconds);
    }

    [Fact]
    public async Task GetCachedAsync_IsUsed_NotExchangeAsync()
    {
        // The config endpoint must never trigger a new corporate API call.
        // It reads from the cache that ExchangeAsync populated.
        var svc = MockCached();
        await Execute(svc: svc);

        await svc.Received(1).GetCachedAsync(Arg.Any<CancellationToken>());
        await svc.DidNotReceive().ExchangeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ── Behavioural knobs ─────────────────────────────────────────────────────

    [Fact]
    public async Task Returns_AllKnobs_FromConfiguration()
    {
        var response = await Execute(
            BuildConfig(refreshBefore: 60, hardStop: 20, maxRetries: 3, backoffMs: 2000));

        Assert.Equal(60,   response.RefreshBeforeSeconds);
        Assert.Equal(20,   response.HardStopBeforeSeconds);
        Assert.Equal(3,    response.MaxRetries);
        Assert.Equal(2000, response.RetryBackoffMs);
    }

    [Fact]
    public async Task Returns_OverriddenKnobs_WhenAppConfigChanges()
    {
        var response = await Execute(
            BuildConfig(refreshBefore: 90, hardStop: 30, maxRetries: 5, backoffMs: 3000));

        Assert.Equal(90,   response.RefreshBeforeSeconds);
        Assert.Equal(30,   response.HardStopBeforeSeconds);
        Assert.Equal(5,    response.MaxRetries);
        Assert.Equal(3000, response.RetryBackoffMs);
    }

    // ── Cross-field invariants ────────────────────────────────────────────────

    [Fact]
    public async Task HardStop_IsLessThan_RefreshBefore()
    {
        var r = await Execute(BuildConfig(refreshBefore: 60, hardStop: 20));
        Assert.True(r.HardStopBeforeSeconds < r.RefreshBeforeSeconds,
            $"HardStop ({r.HardStopBeforeSeconds}) must be less than RefreshBefore ({r.RefreshBeforeSeconds})");
    }

    [Fact]
    public async Task RefreshBefore_IsLessThan_TokenExpiration()
    {
        var r = await Execute(BuildConfig(refreshBefore: 60), MockCached(expiresInMinutes: 10));
        Assert.True(r.RefreshBeforeSeconds < r.TokenExpirationSeconds,
            $"RefreshBefore ({r.RefreshBeforeSeconds}) must be less than TokenExpiration ({r.TokenExpirationSeconds})");
    }

    [Fact]
    public async Task RetryBudget_FitsWithin_AvailableWindow()
    {
        var r = await Execute(BuildConfig(refreshBefore: 60, hardStop: 20, maxRetries: 3, backoffMs: 2000));

        var totalRetryMs = Enumerable
            .Range(0, r.MaxRetries)
            .Sum(i => r.RetryBackoffMs * Math.Pow(2, i));

        var windowMs = (r.RefreshBeforeSeconds - r.HardStopBeforeSeconds) * 1000;

        Assert.True(totalRetryMs < windowMs,
            $"Retry budget ({totalRetryMs}ms) must fit inside window ({windowMs}ms)");
    }
}
