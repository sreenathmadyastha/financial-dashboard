using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace TokenExchangeService
{
    // ===== Configuration Models =====
    public class TokenExchangeConfig
    {
        public string OAuthProviderUrl { get; set; }
        public string ClientId { get; set; }
        public RsaKeyParameters RsaKeyParameters { get; set; }
    }

    public class RsaKeyParameters
    {
        public string Modulus { get; set; }          // n
        public string Exponent { get; set; }         // e (usually "AQAB")
        public string D { get; set; }                // d (private exponent)
        public string P { get; set; }                // p (first prime)
        public string Q { get; set; }                // q (second prime)
        public string DP { get; set; }               // dp (d mod (p-1))
        public string DQ { get; set; }               // dq (d mod (q-1))
        public string InverseQ { get; set; }         // qi (q^-1 mod p)
        public string KeyId { get; set; }            // kid (key identifier)
    }

    // ===== Response Models =====
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
        public string EncryptedProductToken { get; set; }
    }

    // ===== Main Token Exchange Service =====
    public class TokenExchangeService
    {
        private readonly TokenExchangeConfig _config;
        private readonly IDistributedCache _cache;
        private readonly HttpClient _httpClient;
        private readonly byte[] _encryptionKey;
        private readonly RSA _rsaKey;

        public TokenExchangeService(TokenExchangeConfig config, IDistributedCache cache)
        {
            _config = config;
            _cache = cache;
            _httpClient = new HttpClient();

            // Load RSA private key from parameters
            _rsaKey = LoadRsaFromParameters(_config.RsaKeyParameters);

            // Initialize encryption key for storing product tokens securely
            _encryptionKey = DeriveKeyFromRsaParameters(_config.RsaKeyParameters);
        }

        // ===== RSA Key Loading =====

        /// <summary>
        /// Load RSA private key from parameters array (modulus, exponent, etc.)
        /// </summary>
        private RSA LoadRsaFromParameters(RsaKeyParameters keyParams)
        {
            try
            {
                var rsa = RSA.Create();

                var rsaParameters = new RSAParameters
                {
                    Modulus = Base64UrlDecode(keyParams.Modulus),
                    Exponent = Base64UrlDecode(keyParams.Exponent),
                    D = Base64UrlDecode(keyParams.D),
                    P = Base64UrlDecode(keyParams.P),
                    Q = Base64UrlDecode(keyParams.Q),
                    DP = Base64UrlDecode(keyParams.DP),
                    DQ = Base64UrlDecode(keyParams.DQ),
                    InverseQ = Base64UrlDecode(keyParams.InverseQ)
                };

                rsa.ImportParameters(rsaParameters);
                return rsa;
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to load RSA private key from parameters: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Base64Url decode (RFC 4648)
        /// </summary>
        private byte[] Base64UrlDecode(string base64Url)
        {
            if (string.IsNullOrEmpty(base64Url))
                return null;

            // Convert Base64Url to Base64
            var base64 = base64Url
                .Replace('-', '+')
                .Replace('_', '/');

            // Add padding
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }

        // ===== Client Assertion (Actor Token) Creation =====

        /// <summary>
        /// Create JWT client assertion (actor token) for OAuth authentication
        /// This is signed with your RSA private key
        /// </summary>
        private string CreateClientAssertion()
        {
            var now = DateTimeOffset.UtcNow;
            var jti = Guid.NewGuid().ToString();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, _config.ClientId),
                new Claim(JwtRegisteredClaimNames.Iss, _config.ClientId),
                new Claim(JwtRegisteredClaimNames.Aud, _config.OAuthProviderUrl),
                new Claim(JwtRegisteredClaimNames.Jti, jti),
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, now.AddMinutes(5).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            var securityKey = new RsaSecurityKey(_rsaKey)
            {
                KeyId = _config.RsaKeyParameters.KeyId ?? _config.ClientId
            };

            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

            var token = new JwtSecurityToken(
                issuer: _config.ClientId,
                audience: _config.OAuthProviderUrl,
                claims: claims,
                notBefore: now.DateTime,
                expires: now.AddMinutes(5).DateTime,
                signingCredentials: credentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        // ===== Token Exchange with OAuth Provider =====

        /// <summary>
        /// Exchange product token for USER-SPECIFIC access token via company OAuth provider
        /// Uses client assertion (actor token) signed with RSA key for authentication
        /// OAuth provider validates the product token using JWKS endpoint internally
        /// </summary>
        public async Task<string> GetAccessTokenFromOAuthAsync(string productToken)
        {
            try
            {
                // Create client assertion (actor token) signed with RSA private key
                var clientAssertion = CreateClientAssertion();

                var requestData = new Dictionary<string, string>
                {
                    { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                    { "subject_token", productToken },
                    { "subject_token_type", "urn:ietf:params:oauth:token-type:jwt" },
                    { "client_id", _config.ClientId },
                    { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                    { "client_assertion", clientAssertion },
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

        // ===== Product Token Encryption/Decryption =====

        /// <summary>
        /// Derive encryption key from RSA parameters
        /// </summary>
        private byte[] DeriveKeyFromRsaParameters(RsaKeyParameters keyParams)
        {
            using (var sha256 = SHA256.Create())
            {
                var keyMaterial = $"{keyParams.Modulus}{keyParams.D}";
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(keyMaterial));
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

        // ===== Refresh Token Management =====

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
                EncryptedProductToken = EncryptToken(productToken)
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

        // ===== Main Token Exchange Flow =====

        /// <summary>
        /// Main method: Exchange product token for USER-SPECIFIC access + refresh tokens
        /// 1. Exchanges product token with OAuth provider (uses client assertion as actor token)
        /// 2. OAuth provider validates product token internally using JWKS
        /// 3. Stores encrypted product token for future refresh
        /// </summary>
        public async Task<TokenResponse> ExchangeTokenAsync(string productToken)
        {
            try
            {
                Console.WriteLine("Step 1: Creating client assertion (actor token) and exchanging with OAuth provider...");

                // Exchange product token with OAuth provider using client assertion
                var accessToken = await GetAccessTokenFromOAuthAsync(productToken);

                Console.WriteLine("Step 2: Extracting user info from product token...");

                // Decode product token to extract user info (no validation needed - OAuth did it)
                var handler = new JwtSecurityTokenHandler();
                var decodedToken = handler.ReadJwtToken(productToken);

                var userId = decodedToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value
                             ?? decodedToken.Claims.FirstOrDefault(c => c.Type == "userId")?.Value;

                if (string.IsNullOrEmpty(userId))
                {
                    throw new Exception("Product token does not contain user identifier");
                }

                Console.WriteLine("Step 3: Generating refresh token and storing encrypted product token...");

                var metadata = new Dictionary<string, string>
                {
                    { "productTokenId", decodedToken.Claims.FirstOrDefault(c => c.Type == "jti")?.Value ?? "" },
                    { "scope", decodedToken.Claims.FirstOrDefault(c => c.Type == "scope")?.Value ?? "" },
                    { "clientId", decodedToken.Claims.FirstOrDefault(c => c.Type == "aud")?.Value ?? "" }
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
        /// Refresh access token using local refresh token
        /// Re-exchanges the stored product token with OAuth provider using client assertion
        /// </summary>
        public async Task<TokenResponse> RefreshAccessTokenAsync(string refreshToken)
        {
            try
            {
                Console.WriteLine("Step 1: Retrieving refresh token from cache...");

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

                Console.WriteLine("Step 2: Decrypting stored product token...");

                // Decrypt the stored product token
                var productToken = DecryptToken(refreshTokenData.EncryptedProductToken);

                Console.WriteLine("Step 3: Re-exchanging product token with OAuth provider using client assertion...");

                // Re-exchange product token with OAuth provider (creates new client assertion)
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

        // ===== Token Revocation =====

        /// <summary>
        /// Revoke a specific refresh token
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
        /// Revoke all refresh tokens for a specific user
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
    }

    // ===== Usage Example =====
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Setup distributed cache
            var cache = new Microsoft.Extensions.Caching.Memory.MemoryDistributedCache(
                new Microsoft.Extensions.Options.OptionsWrapper<Microsoft.Extensions.Caching.Memory.MemoryDistributedCacheOptions>(
                    new Microsoft.Extensions.Caching.Memory.MemoryDistributedCacheOptions()));

            // Configure with RSA key parameters
            var config = new TokenExchangeConfig
            {
                OAuthProviderUrl = "https://oauth.your-company.com",
                ClientId = "your-client-id",
                RsaKeyParameters = new RsaKeyParameters
                {
                    Modulus = "xGOr-H7A8PPr7zAW...",      // Base64Url encoded
                    Exponent = "AQAB",                    // Usually AQAB (65537)
                    D = "Eq5xpGnNCiwi...",               // Private exponent
                    P = "6jQj31qD...",                   // First prime
                    Q = "1lAQpDS...",                    // Second prime
                    DP = "DhK6-xu...",                   // d mod (p-1)
                    DQ = "L8Yqvs...",                    // d mod (q-1)
                    InverseQ = "GR6cLm...",              // q^-1 mod p
                    KeyId = "key-2024"                   // Key identifier
                }
            };

            var tokenService = new TokenExchangeService(config, cache);

            try
            {
                Console.WriteLine("=== Token Exchange Example ===\n");

                // Step 1: Exchange product token for access + refresh tokens
                var productToken = "eyJhbGc..."; // Token from another application
                var tokens = await tokenService.ExchangeTokenAsync(productToken);

                Console.WriteLine($"\n✓ Access Token: {tokens.AccessToken.Substring(0, 50)}...");
                Console.WriteLine($"✓ Refresh Token: {tokens.RefreshToken.Substring(0, 50)}...");
                Console.WriteLine($"✓ Expires In: {tokens.ExpiresIn} seconds\n");

                // Step 2: Use access token to call protected APIs
                Console.WriteLine("=== Using Access Token ===");
                Console.WriteLine("Now you can call protected APIs with this access token\n");

                // Step 3: Refresh access token when it expires
                Console.WriteLine("=== Refreshing Access Token ===");
                var newTokens = await tokenService.RefreshAccessTokenAsync(tokens.RefreshToken);
                Console.WriteLine($"✓ New Access Token: {newTokens.AccessToken.Substring(0, 50)}...\n");

                // Step 4: Revoke refresh token (logout)
                Console.WriteLine("=== Revoking Refresh Token ===");
                var revoked = await tokenService.RevokeRefreshTokenAsync(tokens.RefreshToken);
                Console.WriteLine($"✓ Refresh token revoked: {revoked}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
            }
        }
    }
}