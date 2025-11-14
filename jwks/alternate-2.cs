using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.IdentityModel.Tokens;

class Program
{
    // CONFIG – Replace these
    private const string KeyVaultUrl = "https://your-vault.vault.azure.net/";
    private const string KeyName = "my-rsa-signing-key";

    static async Task Main(string[] args)
    {
        try
        {
            string token = await CreateJwtWithSecurityTokenAsync();
            Console.WriteLine($"Generated JWT: {token}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Creates a JWT using JwtSecurityToken + SigningCredentials from an exportable Key Vault RSA key.
    /// </summary>
    private static async Task<string> CreateJwtWithSecurityTokenAsync()
    {
        // 1. Auth to Key Vault
        var credential = new DefaultAzureCredential();
        var keyClient = new KeyClient(new Uri(KeyVaultUrl), credential);

        // 2. Fetch the full key (includes private material – only works if exportable)
        KeyVaultKey keyVaultKey = await keyClient.GetKeyAsync(KeyName);  // Latest version

        // 3. Import into local RSA
        RSA rsa = await ImportRsaFromKeyVaultKeyAsync(keyVaultKey);

        // 4. Create SigningCredentials (RS256 = RSA-SHA256)
        var securityKey = new RsaSecurityKey(rsa)
        {
            KeyId = keyVaultKey.Id  // Optional: Adds 'kid' to JWT header for key lookup
        };
        var signingCredentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.RsaSha256);

        // 5. Build claims (easy with JwtSecurityToken!)
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "user123"),
            new Claim(JwtRegisteredClaimNames.Iss, "my-issuer"),
            new Claim(JwtRegisteredClaimNames.Aud, "my-audience"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("role", "admin"),  // Custom claim example
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        var now = DateTime.UtcNow;
        var jwtToken = new JwtSecurityToken(
            issuer: "my-issuer",
            audience: "my-audience",
            claims: claims,
            notBefore: now,
            expires: now.AddMinutes(60),  // 1 hour expiry
            signingCredentials: signingCredentials);

        // 6. Serialize to string
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(jwtToken);
    }

    /// <summary>
    /// Imports Key Vault's JsonWebKey into a local RSA instance.
    /// </summary>
    private static async Task<RSA> ImportRsaFromKeyVaultKeyAsync(KeyVaultKey keyVaultKey)
    {
        // Fetch the *full* key if not already (includes private params)
        if (keyVaultKey.Key == null || keyVaultKey.Key.D == null)
        {
            // Re-fetch with explicit version if needed; assumes exportable
            var keyClient = new KeyClient(new Uri(keyVaultKey.VaultUri), new DefaultAzureCredential());
            keyVaultKey = await keyClient.GetKeyAsync(keyVaultKey.Name, keyVaultKey.Properties.Version);
        }

        var jwk = keyVaultKey.Key;  // JsonWebKey with N, E, D, etc.

        if (jwk.KeyType != KeyType.Rsa && jwk.KeyType != KeyType.RsaHsm)
            throw new InvalidOperationException("Key must be RSA type.");

        var rsa = RSA.Create();
        var parameters = new RSAParameters
        {
            Modulus = jwk.N,           // Public modulus
            Exponent = jwk.E,          // Public exponent
            D = jwk.D,                 // Private exponent
            P = jwk.P,                 // Prime 1
            Q = jwk.Q,                 // Prime 2
            DP = jwk.DP,               // D mod (P-1)
            DQ = jwk.DQ,               // D mod (Q-1)
            InverseQ = jwk.QInv        // Q^-1 mod P
        };

        rsa.ImportParameters(parameters);
        return rsa;
    }
}