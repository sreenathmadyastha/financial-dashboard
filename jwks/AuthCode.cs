using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

// ===== Program.cs Configuration =====
public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to container
        builder.Services.AddControllers();

        // Configure distributed cache (Redis in production)
        builder.Services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = builder.Configuration["Redis:ConnectionString"];
            options.InstanceName = "TokenCache:";
        });
        // Or use memory cache for development
        // builder.Services.AddDistributedMemoryCache();

        // Register token services
        var rsaKeySection = builder.Configuration.GetSection("TokenExchange:RsaKey");
        builder.Services.AddSingleton(new TokenExchangeConfig
        {
            JwksUri = builder.Configuration["TokenExchange:JwksUri"],
            OAuthProviderUrl = builder.Configuration["TokenExchange:OAuthProviderUrl"],
            ClientId = builder.Configuration["TokenExchange:ClientId"],
            RsaKeyParameters = new RsaKeyParameters
            {
                Modulus = rsaKeySection["Modulus"],
                Exponent = rsaKeySection["Exponent"],
                D = rsaKeySection["D"],
                P = rsaKeySection["P"],
                Q = rsaKeySection["Q"],
                DP = rsaKeySection["DP"],
                DQ = rsaKeySection["DQ"],
                InverseQ = rsaKeySection["InverseQ"],
                KeyId = rsaKeySection["KeyId"]
            }
        });

        builder.Services.AddSingleton<TokenExchangeService>();
        builder.Services.AddSingleton<AccessTokenValidator>();
        builder.Services.AddHttpClient<AuthenticatedApiClient>();

        // Configure JWT Bearer Authentication
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = builder.Configuration["TokenExchange:OAuthProviderUrl"];
                options.Audience = builder.Configuration["TokenExchange:ClientId"];
                options.RequireHttpsMetadata = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                // Custom token validation events
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        Console.WriteLine("Token validated successfully");
                        return Task.CompletedTask;
                    }
                };
            });

        builder.Services.AddAuthorization(options =>
        {
            // Define policy for finance data access
            options.AddPolicy("FinanceRead", policy =>
                policy.RequireClaim("scope", "finance.read"));

            // Define policy for admin access
            options.AddPolicy("AdminAccess", policy =>
                policy.RequireClaim("scope", "admin"));
        });

        var app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}

// ===== Token Exchange Controller =====
[ApiController]
[Route("api/[controller]")]
public class TokenController : ControllerBase
{
    private readonly TokenExchangeService _tokenService;

    public TokenController(TokenExchangeService tokenService)
    {
        _tokenService = tokenService;
    }

    /// <summary>
    /// Exchange product token for access and refresh tokens
    /// POST /api/token/exchange
    /// </summary>
    [HttpPost("exchange")]
    [AllowAnonymous]
    public async Task<ActionResult<TokenResponse>> Exchange([FromBody] TokenExchangeRequest request)
    {
        try
        {
            var tokens = await _tokenService.ExchangeTokenAsync(request.ProductToken);
            return Ok(tokens);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Refresh access token using refresh token
    /// POST /api/token/refresh
    /// </summary>
    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<ActionResult<TokenResponse>> Refresh([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var tokens = await _tokenService.RefreshAccessTokenAsync(request.RefreshToken);
            return Ok(tokens);
        }
        catch (Exception ex)
        {
            return Unauthorized(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Revoke refresh token (logout)
    /// POST /api/token/revoke
    /// </summary>
    [HttpPost("revoke")]
    [Authorize]
    public async Task<IActionResult> Revoke([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var revoked = await _tokenService.RevokeRefreshTokenAsync(request.RefreshToken);
            return Ok(new { success = revoked });
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Revoke all refresh tokens for current user
    /// POST /api/token/revoke-all
    /// </summary>
    [HttpPost("revoke-all")]
    [Authorize]
    public async Task<IActionResult> RevokeAll()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var count = await _tokenService.RevokeAllUserTokensAsync(userId);
            return Ok(new { revokedTokens = count });
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}

// ===== Finance API Controller (Protected) =====
[ApiController]
[Route("api/[controller]")]
[Authorize] // Requires valid access token
public class FinanceController : ControllerBase
{
    private readonly AuthenticatedApiClient _apiClient;

    public FinanceController(AuthenticatedApiClient apiClient)
    {
        _apiClient = apiClient;
    }

    /// <summary>
    /// Get finance data - requires finance.read scope
    /// GET /api/finance/accounts
    /// </summary>
    [HttpGet("accounts")]
    [Authorize(Policy = "FinanceRead")]
    public async Task<IActionResult> GetAccounts()
    {
        try
        {
            // Get access token from request header
            var accessToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            // Call external finance API
            var financeData = await _apiClient.GetFinanceDataAsync(
                accessToken,
                "https://api.company.com/finance/accounts");

            return Ok(financeData);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Forbid(ex.Message);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }

    /// <summary>
    /// Get transaction history
    /// GET /api/finance/transactions
    /// </summary>
    [HttpGet("transactions")]
    [Authorize(Policy = "FinanceRead")]
    public async Task<IActionResult> GetTransactions([FromQuery] DateTime? startDate, [FromQuery] DateTime? endDate)
    {
        try
        {
            var accessToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            var queryParams = $"?userId={userId}";
            if (startDate.HasValue) queryParams += $"&startDate={startDate.Value:yyyy-MM-dd}";
            if (endDate.HasValue) queryParams += $"&endDate={endDate.Value:yyyy-MM-dd}";

            var transactions = await _apiClient.CallAuthenticatedApiAsync<List<Transaction>>(
                accessToken,
                $"https://api.company.com/finance/transactions{queryParams}",
                HttpMethod.Get,
                "finance.read");

            return Ok(transactions);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }

    /// <summary>
    /// Create a new transaction
    /// POST /api/finance/transactions
    /// </summary>
    [HttpPost("transactions")]
    [Authorize(Policy = "FinanceRead")]
    public async Task<IActionResult> CreateTransaction([FromBody] CreateTransactionRequest request)
    {
        try
        {
            var accessToken = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            var result = await _apiClient.CallAuthenticatedApiAsync<Transaction>(
                accessToken,
                "https://api.company.com/finance/transactions",
                HttpMethod.Post,
                "finance.write",
                request);

            return CreatedAtAction(nameof(GetTransactions), new { id = result.Id }, result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }
}

// ===== Custom Authorization Middleware =====
public class TokenValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AccessTokenValidator _tokenValidator;

    public TokenValidationMiddleware(RequestDelegate next, AccessTokenValidator tokenValidator)
    {
        _next = next;
        _tokenValidator = tokenValidator;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip validation for anonymous endpoints
        var endpoint = context.GetEndpoint();
        if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
        {
            await _next(context);
            return;
        }

        // Extract token from Authorization header
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (authHeader?.StartsWith("Bearer ") == true)
        {
            var token = authHeader.Substring("Bearer ".Length).Trim();

            try
            {
                // Validate the token
                var validatedToken = await _tokenValidator.ValidateAccessTokenAsync(token);

                // Add user info to context
                var userId = _tokenValidator.GetUserIdFromToken(validatedToken);
                context.Items["UserId"] = userId;
                context.Items["ValidatedToken"] = validatedToken;
            }
            catch (SecurityTokenValidationException)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsJsonAsync(new { error = "Invalid or expired token" });
                return;
            }
        }

        await _next(context);
    }
}

// ===== Request/Response Models =====
public class TokenExchangeRequest
{
    public string ProductToken { get; set; }
}

public class RefreshTokenRequest
{
    public string RefreshToken { get; set; }
}

public class CreateTransactionRequest
{
    public decimal Amount { get; set; }
    public string Description { get; set; }
    public string Category { get; set; }
}

public class Transaction
{
    public string Id { get; set; }
    public decimal Amount { get; set; }
    public string Description { get; set; }
    public DateTime Date { get; set; }
}

// ===== Extension Methods =====
public static class HttpContextExtensions
{
    public static string GetUserId(this HttpContext context)
    {
        return context.Items["UserId"]?.ToString();
    }

    public static string GetAccessToken(this HttpContext context)
    {
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        return authHeader?.Replace("Bearer ", "").Trim();
    }
}