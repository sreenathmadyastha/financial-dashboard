using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace TokenExchangeService
{
    public class TokenExchangeConfig
    {
        public string JwksUri { get; set; }
        public string PrivateKey { get; set; }
        public string OAuthProviderUrl { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }

    public class TokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresIn { get; set; } = 3600;
    }

    public class RefreshTokenData
    {
        public string Token { get; set; }
        public string UserId { get; set; }
        public Dictionary<string, string> Metadata { get; set; }
        public long CreatedAt { get; set; }
        public long ExpiresAt { get; set; }

        // Store encrypted product token for re-exchange
        public string EncryptedProductToken { get; set; }
    }

    public class TokenExchangeService
    {
        private readonly TokenExchangeConfig _config;
        private readonly IDistributedCache _cache;
        private readonly HttpClient _httpClient;
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configManager;
        private readonly byte[] _encryptionKey;

        public TokenExchangeService(TokenExchangeConfig config, IDistributedCache cache)
        {
            _config = config;
            _cache = cache;
            _httpClient = new HttpClient();

            // Initialize JWKS configuration manager
            _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                _config.JwksUri,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());

            // Initialize encryption key for storing product tokens securely
            // In production, load this from secure configuration (Azure Key Vault, AWS Secrets Manager, etc.)
            _encryptionKey = DeriveKeyFromConfig(_config.PrivateKey);
        }

        /// <summary>
        /// Derive encryption key from configuration
        /// </summary>
        private byte[] DeriveKeyFromConfig(string secret)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
            }
        }

        /// <summary>
        /// Encrypt product token for secure storage
        /// </summary>
        private string EncryptToken(string token)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _encryptionKey;
                aes.GenerateIV();

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new System.IO.MemoryStream())
                {
                    // Write IV first
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var writer = new System.IO.StreamWriter(cs))
                    {
                        writer.Write(token);
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        /// <summary>
        /// Decrypt product token from storage
        /// </summary>
        private string DecryptToken(string encryptedToken)
        {
            var buffer = Convert.FromBase64String(encryptedToken);

            using (var aes = Aes.Create())
            {
                aes.Key = _encryptionKey;

                // Extract IV from beginning of buffer
                var iv = new byte[aes.IV.Length];
                Array.Copy(buffer, 0, iv, 0, iv.Length);
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new System.IO.MemoryStream(buffer, iv.Length, buffer.Length - iv.Length))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var reader = new System.IO.StreamReader(cs))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// Validate the product token from another application
        /// </summary>
        public async Task<JwtSecurityToken> ValidateProductTokenAsync(string productToken)
        {
            try
            {
                var config = await _configManager.GetConfigurationAsync();

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = config.SigningKeys,
                    ValidateIssuer = true,
                    ValidIssuers = new[] { config.Issuer },
                    ValidateAudience = false, // Configure based on your needs
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(productToken, validationParameters, out var validatedToken);

                return validatedToken as JwtSecurityToken;
            }
            catch (Exception ex)
            {
                throw new Exception($"Product token validation failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Exchange product token for USER-SPECIFIC access token via company OAuth provider
        /// OAuth provider will validate the product token using JWKS endpoint internally
        /// </summary>
        public async Task<string> GetAccessTokenFromOAuthAsync(string productToken)
        {
            try
            {
                var requestData = new Dictionary<string, string>
                {
                    { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                    { "subject_token", productToken }, // Pass the JWT directly - OAuth validates it
                    { "subject_token_type", "urn:ietf:params:oauth:token-type:jwt" },
                    { "client_id", _config.ClientId },
                    { "client_secret", _config.ClientSecret },
                    { "requested_token_type", "urn:ietf:params:oauth:token-type:access_token" }
                };

                var content = new FormUrlEncodedContent(requestData);
                var response = await _httpClient.PostAsync($"{_config.OAuthProviderUrl}/token", content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    throw new Exception($"OAuth token exchange failed: {response.StatusCode} - {errorContent}");
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(responseContent);

                return tokenResponse["access_token"].GetString();
            }
            catch (Exception ex)
            {
                throw new Exception($"OAuth token exchange failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Generate a local refresh token and store encrypted product token
        /// </summary>
        public async Task<string> GenerateRefreshTokenAsync(string userId, string productToken, Dictionary<string, string> metadata = null)
        {
            var refreshToken = GenerateSecureToken();

            var refreshTokenData = new RefreshTokenData
            {
                Token = refreshToken,
                UserId = userId,
                Metadata = metadata ?? new Dictionary<string, string>(),
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeMilliseconds(),
                EncryptedProductToken = EncryptToken(productToken) // Store encrypted product token
            };

            // Store in cache
            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = DateTimeOffset.UtcNow.AddDays(30)
            };

            var serializedData = JsonSerializer.Serialize(refreshTokenData);
            await _cache.SetStringAsync(refreshToken, serializedData, cacheOptions);

            // Maintain user-to-tokens mapping
            var userTokensKey = $"user:{userId}:refresh_tokens";
            var existingTokensJson = await _cache.GetStringAsync(userTokensKey);
            var userTokens = string.IsNullOrEmpty(existingTokensJson)
                ? new List<string>()
                : JsonSerializer.Deserialize<List<string>>(existingTokensJson);

            userTokens.Add(refreshToken);
            await _cache.SetStringAsync(userTokensKey, JsonSerializer.Serialize(userTokens), cacheOptions);

            return refreshToken;
        }

        /// <summary>
        /// Main method: Exchange product token for USER-SPECIFIC access + refresh tokens
        /// Stores encrypted product token for future re-exchange
        /// </summary>
        public async Task<TokenResponse> ExchangeTokenAsync(string productToken)
        {
            try
            {
                // Step 1: Validate the product token
                Console.WriteLine("Step 1: Validating product token...");
                var productTokenPayload = await ValidateProductTokenAsync(productToken);

                // Step 2: Exchange for USER-SPECIFIC access token via OAuth provider
                Console.WriteLine("Step 2: Exchanging for user-specific access token...");
                var accessToken = await GetAccessTokenFromOAuthAsync(productTokenPayload, productToken);

                // Step 3: Generate local refresh token and store encrypted product token
                Console.WriteLine("Step 3: Generating refresh token and storing product token...");
                var userId = productTokenPayload.Claims.FirstOrDefault(c => c.Type == "sub")?.Value
                             ?? productTokenPayload.Claims.FirstOrDefault(c => c.Type == "userId")?.Value;

                var metadata = new Dictionary<string, string>
                {
                    { "productTokenId", productTokenPayload.Claims.FirstOrDefault(c => c.Type == "jti")?.Value ?? "" },
                    { "scope", productTokenPayload.Claims.FirstOrDefault(c => c.Type == "scope")?.Value ?? "" },
                    { "clientId", productTokenPayload.Claims.FirstOrDefault(c => c.Type == "aud")?.Value ?? "" }
                };

                // Store encrypted product token for re-exchange when access token expires
                var refreshToken = await GenerateRefreshTokenAsync(userId, productToken, metadata);

                return new TokenResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    TokenType = "Bearer",
                    ExpiresIn = 3600
                };
            }
            catch (Exception ex)
            {
                throw new Exception($"Token exchange failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Validate and use refresh token to get new USER-SPECIFIC access token
        /// Re-exchanges the stored product token with OAuth provider (which validates it)
        /// </summary>
        public async Task<TokenResponse> RefreshAccessTokenAsync(string refreshToken)
        {
            try
            {
                // Retrieve refresh token from cache
                var refreshTokenJson = await _cache.GetStringAsync(refreshToken);

                if (string.IsNullOrEmpty(refreshTokenJson))
                {
                    throw new Exception("Invalid or expired refresh token");
                }

                var refreshTokenData = JsonSerializer.Deserialize<RefreshTokenData>(refreshTokenJson);

                // Check expiration
                if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > refreshTokenData.ExpiresAt)
                {
                    await _cache.RemoveAsync(refreshToken);
                    throw new Exception("Refresh token expired");
                }

                // Decrypt the stored product token
                var productToken = DecryptToken(refreshTokenData.EncryptedProductToken);

                // Re-exchange product token with OAuth provider
                // OAuth provider will validate it using JWKS internally
                var newAccessToken = await GetAccessTokenFromOAuthAsync(productToken);

                return new TokenResponse
                {
                    AccessToken = newAccessToken,
                    TokenType = "Bearer",
                    ExpiresIn = 3600
                };
            }
            catch (Exception ex) when (ex.Message.Contains("invalid_token") || ex.Message.Contains("expired"))
            {
                // Product token has expired or is invalid, user needs to re-authenticate
                await _cache.RemoveAsync(refreshToken);
                throw new Exception("Product token expired, re-authentication required", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Token refresh failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Revoke refresh token
        /// </summary>
        public async Task<bool> RevokeRefreshTokenAsync(string refreshToken)
        {
            var refreshTokenJson = await _cache.GetStringAsync(refreshToken);

            if (!string.IsNullOrEmpty(refreshTokenJson))
            {
                var refreshTokenData = JsonSerializer.Deserialize<RefreshTokenData>(refreshTokenJson);

                // Remove from cache
                await _cache.RemoveAsync(refreshToken);

                // Remove from user's token list
                var userTokensKey = $"user:{refreshTokenData.UserId}:refresh_tokens";
                var userTokensJson = await _cache.GetStringAsync(userTokensKey);

                if (!string.IsNullOrEmpty(userTokensJson))
                {
                    var userTokens = JsonSerializer.Deserialize<List<string>>(userTokensJson);
                    userTokens.Remove(refreshToken);
                    await _cache.SetStringAsync(userTokensKey, JsonSerializer.Serialize(userTokens));
                }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Revoke all refresh tokens for a user
        /// </summary>
        public async Task<int> RevokeAllUserTokensAsync(string userId)
        {
            var userTokensKey = $"user:{userId}:refresh_tokens";
            var userTokensJson = await _cache.GetStringAsync(userTokensKey);

            if (string.IsNullOrEmpty(userTokensJson))
            {
                return 0;
            }

            var userTokens = JsonSerializer.Deserialize<List<string>>(userTokensJson);

            foreach (var token in userTokens)
            {
                await _cache.RemoveAsync(token);
            }

            await _cache.RemoveAsync(userTokensKey);
            return userTokens.Count;
        }

        /// <summary>
        /// Generate a cryptographically secure random token
        /// </summary>
        private string GenerateSecureToken()
        {
            var randomBytes = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes);
        }
    }

    /// <summary>
    /// Service for validating access tokens from OAuth provider
    /// </summary>
    public class AccessTokenValidator
    {
        private readonly TokenExchangeConfig _config;
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configManager;

        public AccessTokenValidator(TokenExchangeConfig config)
        {
            _config = config;

            // Initialize configuration manager for OAuth provider's JWKS
            _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{_config.OAuthProviderUrl}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());
        }

        /// <summary>
        /// Validate access token issued by OAuth provider
        /// </summary>
        public async Task<JwtSecurityToken> ValidateAccessTokenAsync(string accessToken)
        {
            try
            {
                var config = await _configManager.GetConfigurationAsync();

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = config.SigningKeys,
                    ValidateIssuer = true,
                    ValidIssuer = config.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _config.ClientId, // Your API audience
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(accessToken, validationParameters, out var validatedToken);

                return validatedToken as JwtSecurityToken;
            }
            catch (Exception ex)
            {
                throw new SecurityTokenValidationException($"Access token validation failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Extract user ID from validated token
        /// </summary>
        public string GetUserIdFromToken(JwtSecurityToken token)
        {
            return token.Claims.FirstOrDefault(c => c.Type == "sub")?.Value
                   ?? token.Claims.FirstOrDefault(c => c.Type == "userId")?.Value;
        }

        /// <summary>
        /// Check if token has required scope
        /// </summary>
        public bool HasScope(JwtSecurityToken token, string requiredScope)
        {
            var scopes = token.Claims
                .Where(c => c.Type == "scope")
                .SelectMany(c => c.Value.Split(' '))
                .ToList();

            return scopes.Contains(requiredScope);
        }
    }

    /// <summary>
    /// HTTP Client for calling external APIs with access token
    /// </summary>
    public class AuthenticatedApiClient
    {
        private readonly HttpClient _httpClient;
        private readonly AccessTokenValidator _tokenValidator;

        public AuthenticatedApiClient(HttpClient httpClient, AccessTokenValidator tokenValidator)
        {
            _httpClient = httpClient;
            _tokenValidator = tokenValidator;
        }

        /// <summary>
        /// Call external API (e.g., Finance API) with access token
        /// </summary>
        public async Task<string> GetFinanceDataAsync(string accessToken, string endpoint)
        {
            try
            {
                // Validate the access token before using it
                var validatedToken = await _tokenValidator.ValidateAccessTokenAsync(accessToken);

                // Check if token has required scope for finance data
                if (!_tokenValidator.HasScope(validatedToken, "finance.read"))
                {
                    throw new UnauthorizedAccessException("Token does not have finance.read scope");
                }

                // Use the access token to call external API
                _httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                var response = await _httpClient.GetAsync(endpoint);
                response.EnsureSuccessStatusCode();

                return await response.Content.ReadAsStringAsync();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to get finance data: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Generic method to call any authenticated API
        /// </summary>
        public async Task<T> CallAuthenticatedApiAsync<T>(
            string accessToken,
            string apiUrl,
            HttpMethod method,
            string requiredScope = null,
            object requestBody = null)
        {
            // Validate the access token
            var validatedToken = await _tokenValidator.ValidateAccessTokenAsync(accessToken);

            // Check scope if required
            if (!string.IsNullOrEmpty(requiredScope) && !_tokenValidator.HasScope(validatedToken, requiredScope))
            {
                throw new UnauthorizedAccessException($"Token does not have required scope: {requiredScope}");
            }

            // Prepare request
            var request = new HttpRequestMessage(method, apiUrl);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            if (requestBody != null)
            {
                var jsonContent = JsonSerializer.Serialize(requestBody);
                request.Content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
            }

            // Make API call
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<T>(responseContent);
        }
    }

    // Usage Example
    //     public class Program
    //     {
    //         public static async Task Main(string[] args)
    //         {
    //             // Setup dependency injection (example with memory cache)
    //             var cache = new Microsoft.Extensions.Caching.Memory.MemoryDistributedCache(
    //                 new Microsoft.Extensions.Options.OptionsWrapper<Microsoft.Extensions.Caching.Memory.MemoryDistributedCacheOptions>(
    //                     new Microsoft.Extensions.Caching.Memory.MemoryDistributedCacheOptions()));

//             var config = new TokenExchangeConfig
//             {
//                 JwksUri = "https://your-company.com/.well-known/jwks.json",
//                 PrivateKey = Environment.GetEnvironmentVariable("PRIVATE_KEY"),
//                 OAuthProviderUrl = "https://oauth.your-company.com",
//                 ClientId = "your-client-id",
//                 ClientSecret = "your-client-secret"
//             };

//             var tokenService = new TokenExchangeService(config, cache);
//             var tokenValidator = new AccessTokenValidator(config);
//             var httpClient = new HttpClient();
//             var apiClient = new AuthenticatedApiClient(httpClient, tokenValidator);

//             try
//             {
//                 // Step 1: Exchange product token for access + refresh tokens
//                 var productToken = "eyJhbGc..."; // Token from another application
//                 var tokens = await tokenService.ExchangeTokenAsync(productToken);

//                 Console.WriteLine($"Access Token: {tokens.AccessToken}");
//                 Console.WriteLine($"Refresh Token: {tokens.RefreshToken}");

//                 // Step 2: Use access token to call Finance API
//                 var financeData = await apiClient.GetFinanceDataAsync(
//                     tokens.AccessToken,
//                     "https://api.company.com/finance/accounts");

//                 Console.WriteLine($"Finance Data: {financeData}");

//                 // Step 3: Generic API call with scope validation
//                 var userData = await apiClient.CallAuthenticatedApiAsync<Dictionary<string, object>>(
//                     tokens.AccessToken,
//                     "https://api.company.com/user/profile",
//                     HttpMethod.Get,
//                     "profile.read");

//                 // Step 4: Refresh access token when it expires
//                 var newTokens = await tokenService.RefreshAccessTokenAsync(tokens.RefreshToken);
//                 Console.WriteLine($"New Access Token: {newTokens.AccessToken}");

//                 // Step 5: Revoke refresh token on logout
//                 await tokenService.RevokeRefreshTokenAsync(tokens.RefreshToken);
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Error: {ex.Message}");
//             }
//         }
//     }
// }

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

