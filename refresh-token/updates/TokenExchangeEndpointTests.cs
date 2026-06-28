using FastEndpoints;
using FastEndpoints.Testing;
using Insights.Auth.Endpoints;
using Insights.Auth.Models;
using Insights.Auth.Services;
using Microsoft.Extensions.Configuration;
using NSubstitute;
using Xunit;

namespace Insights.Auth.Tests;

public class TokenExchangeEndpointTests
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

    private static ICorporateTokenService MockExchange(
        string accessToken     = "api-token-xyz",
        int expiresInMinutes   = 10)
    {
        var svc = Substitute.For<ICorporateTokenService>();
        svc.ExchangeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(new CorporateTokenResponse
           {
               AccessToken      = accessToken,
               ExpiresInMinutes = expiresInMinutes
           });
        return svc;
    }

    private static async Task<TokenExchangeResponse> Execute(
        TokenExchangeRequest req,
        IConfiguration? config = null,
        ICorporateTokenService? svc = null)
    {
        var ep = Factory.Create<TokenExchangeEndpoint>(
            svc  ?? MockExchange(),
            config ?? BuildConfig());
        await ep.HandleAsync(req, CancellationToken.None);
        return ep.Response;
    }

    // ── Token exchange ────────────────────────────────────────────────────────

    [Fact]
    public async Task Returns_ApiToken_FromCorporateService()
    {
        var response = await Execute(
            new TokenExchangeRequest { ProductToken = "prod-token-abc" },
            svc: MockExchange(accessToken: "api-token-xyz"));

        Assert.Equal("api-token-xyz", response.ApiToken);
    }

    [Fact]
    public async Task PassesProductToken_ToCorporateService()
    {
        var svc = MockExchange();
        await Execute(new TokenExchangeRequest { ProductToken = "prod-token-abc" }, svc: svc);

        await svc.Received(1).ExchangeAsync(
            "prod-token-abc",
            Arg.Any<CancellationToken>());
    }

    // ── Minutes → seconds conversion ─────────────────────────────────────────

    [Theory]
    [InlineData(5,  300)]
    [InlineData(10, 600)]
    [InlineData(15, 900)]
    [InlineData(30, 1800)]
    public async Task TokenExpirationSeconds_ConvertsMinutesToSeconds(
        int expiresInMinutes, int expectedSeconds)
    {
        var response = await Execute(
            new TokenExchangeRequest { ProductToken = "tok" },
            svc: MockExchange(expiresInMinutes: expiresInMinutes));

        Assert.Equal(expectedSeconds, response.TokenExpirationSeconds);
    }

    // ── Scheduling parameters come from App Configuration ─────────────────────

    [Fact]
    public async Task Returns_AllSchedulingParams_FromConfiguration()
    {
        var response = await Execute(
            new TokenExchangeRequest { ProductToken = "tok" },
            config: BuildConfig(refreshBefore: 60, hardStop: 20, maxRetries: 3, backoffMs: 2000));

        Assert.Equal(60,   response.RefreshBeforeSeconds);
        Assert.Equal(20,   response.HardStopBeforeSeconds);
        Assert.Equal(3,    response.MaxRetries);
        Assert.Equal(2000, response.RetryBackoffMs);
    }

    // ── Cross-field invariants ────────────────────────────────────────────────

    [Fact]
    public async Task RefreshBefore_IsLessThan_TokenExpiration()
    {
        var response = await Execute(
            new TokenExchangeRequest { ProductToken = "tok" },
            config: BuildConfig(refreshBefore: 60),
            svc: MockExchange(expiresInMinutes: 10)); // 600s

        Assert.True(
            response.RefreshBeforeSeconds < response.TokenExpirationSeconds,
            $"RefreshBeforeSeconds ({response.RefreshBeforeSeconds}) must be less than " +
            $"TokenExpirationSeconds ({response.TokenExpirationSeconds})");
    }

    [Fact]
    public async Task HardStop_IsLessThan_RefreshBefore()
    {
        var response = await Execute(
            new TokenExchangeRequest { ProductToken = "tok" },
            config: BuildConfig(refreshBefore: 60, hardStop: 20));

        Assert.True(
            response.HardStopBeforeSeconds < response.RefreshBeforeSeconds,
            $"HardStopBeforeSeconds ({response.HardStopBeforeSeconds}) must be less than " +
            $"RefreshBeforeSeconds ({response.RefreshBeforeSeconds})");
    }

    [Fact]
    public async Task RetryBudget_FitsWithin_AvailableWindow()
    {
        var response = await Execute(
            new TokenExchangeRequest { ProductToken = "tok" },
            config: BuildConfig(refreshBefore: 60, hardStop: 20, maxRetries: 3, backoffMs: 2000));

        var totalRetryMs = Enumerable
            .Range(0, response.MaxRetries)
            .Sum(i => response.RetryBackoffMs * Math.Pow(2, i));

        var windowMs = (response.RefreshBeforeSeconds - response.HardStopBeforeSeconds) * 1000;

        Assert.True(totalRetryMs < windowMs,
            $"Retry budget ({totalRetryMs}ms) must fit inside window ({windowMs}ms)");
    }

    // ── ExchangeAsync is called exactly once ──────────────────────────────────

    [Fact]
    public async Task CorporateService_ExchangeAsync_CalledExactlyOnce()
    {
        var svc = MockExchange();
        await Execute(new TokenExchangeRequest { ProductToken = "tok" }, svc: svc);

        await svc.Received(1).ExchangeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetCachedAsync_IsNeverCalled_ByExchangeEndpoint()
    {
        // The exchange endpoint must not read from cache — it populates it.
        var svc = MockExchange();
        await Execute(new TokenExchangeRequest { ProductToken = "tok" }, svc: svc);

        await svc.DidNotReceive().GetCachedAsync(Arg.Any<CancellationToken>());
    }
}
