using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;

public class KeyVaultJwtService
{
    private readonly string _vaultUri;
    private readonly string _keyName;
    private readonly CryptographyClient _cryptoClient;

    public KeyVaultJwtService(string vaultUri, string keyName)
    {
        _vaultUri = vaultUri; // e.g., "https://myvault.vault.azure.net/"
        _keyName = keyName;   // e.g., "my-signing-key"

        var credential = new DefaultAzureCredential();
        var keyClient = new KeyClient(new Uri(_vaultUri), credential);
        var key = keyClient.GetKey(_keyName);
        _cryptoClient = new CryptographyClient(key.Id, credential);
    }

    /// <summary>
    /// Creates a signed JWT using JwtSecurityTokenHandler with Key Vault signing.
    /// </summary>
    public string CreateSignedJwt(ClaimsIdentity claimsIdentity, string issuer, string audience, TimeSpan expiresIn)
    {
        // Dummy RSA key (not used for actual signing)
        var dummyRsa = RSA.Create();
        var securityKey = new RsaSecurityKey(dummyRsa);

        // Custom factory and provider for Key Vault integration
        var cryptoFactory = new KeyVaultCryptoProviderFactory(_cryptoClient);
        var signingCredentials = new SigningCredentials(
            securityKey,
            SecurityAlgorithms.RsaSha256,
            SecurityAlgorithms.Sha256Digest) // Specifies SHA-256 hashing
        {
            CryptoProviderFactory = cryptoFactory
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = claimsIdentity,
            Expires = DateTimeOffset.UtcNow.Add(expiresIn).UtcDateTime,
            SigningCredentials = signingCredentials,
            Issuer = issuer,
            Audience = audience
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}

/// <summary>
/// Custom factory to provide Key Vault signature provider.
/// </summary>
public class KeyVaultCryptoProviderFactory : CryptoProviderFactory
{
    private readonly CryptographyClient _cryptoClient;

    public KeyVaultCryptoProviderFactory(CryptographyClient cryptoClient)
    {
        _cryptoClient = cryptoClient;
    }

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
    {
        if (algorithm != SecurityAlgorithms.RsaSha256)
            throw new NotSupportedException($"Algorithm {algorithm} not supported.");

        return new KeyVaultSignatureProvider(_cryptoClient, algorithm);
    }
}

/// <summary>
/// Custom provider that signs via Key Vault.
/// Implements synchronous Sign/Verify, wrapping async calls.
/// </summary>
public class KeyVaultSignatureProvider : SignatureProvider
{
    private readonly CryptographyClient _cryptoClient;
    private readonly string _algorithm;

    public KeyVaultSignatureProvider(CryptographyClient cryptoClient, string algorithm)
        : base(algorithm)
    {
        _cryptoClient = cryptoClient;
        _algorithm = algorithm;
    }

    public override byte[] Sign(byte[] data)
    {
        // For RS256: Hash the full data (header.payload) with SHA-256
        byte[] hash;
        using (var sha256 = SHA256.Create())
        {
            hash = sha256.ComputeHash(data);
        }

        // Sign the hash via Key Vault (wrap async in sync for handler compatibility)
        var signResult = _cryptoClient.SignAsync(SignatureAlgorithm.RS256, hash)
            .GetAwaiter().GetResult();

        return signResult.Value.Signature;
    }

    public override bool Verify(byte[] data, byte[] signature)
    {
        byte[] hash;
        using (var sha256 = SHA256.Create())
        {
            hash = sha256.ComputeHash(data);
        }

        var verifyResult = _cryptoClient.VerifyAsync(SignatureAlgorithm.RS256, hash, signature)
            .GetAwaiter().GetResult();

        return verifyResult.Value.IsValid;
    }
}