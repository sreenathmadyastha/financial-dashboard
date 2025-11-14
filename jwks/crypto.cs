private static async Task<string> CreateJwtViaKeyVaultAsync()
{
    var kvClient = new KeyClient(new Uri(KeyVaultUrl), new DefaultAzureCredential());
    var cryptoClient = new CryptographyClient(new Uri(kvKey.Id), new DefaultAzureCredential());

    // Build header + payload (Base64Url encoded)
    var header = new { alg = "RS256", typ = "JWT", kid = kvKey.Id };
    var payload = new
    {
        iss = "my-api",
        aud = "my-client",
        sub = "user123",
        iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        exp = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds(),
        jti = Guid.NewGuid().ToString()
    };

    string headerB64 = Base64UrlEncode(JsonSerializer.Serialize(header));
    string payloadB64 = Base64UrlEncode(JsonSerializer.Serialize(payload));
    string unsigned = $"{headerB64}.{payloadB64}";

    // Ask Key Vault to sign the hash (SHA-256)
    byte[] dataToSign = Encoding.UTF8.GetBytes(unsigned);
    var hash = SHA256.HashData(dataToSign);

    SignResult signResult = await cryptoClient.SignAsync(SignatureAlgorithm.RS256, hash);
    string signatureB64 = Base64UrlEncode(signResult.Signature);

    return $"{unsigned}.{signatureB64}";
}

// Helper
private static string Base64UrlEncode(string input) =>
    Convert.ToBase64String(Encoding.UTF8.GetBytes(input))
           .TrimEnd('=').Replace('+', '-').Replace('/', '_');