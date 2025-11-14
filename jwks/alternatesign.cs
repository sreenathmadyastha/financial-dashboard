// --------------------------------------------------------------------
private static async Task<string> CreateJwtAsync()
{
    // 1. Authenticate to Key Vault
    var kvClient = new KeyClient(new Uri(KeyVaultUrl), new DefaultAzureCredential());

    // 2. Get the key (public part + metadata)
    KeyVaultKey key = await kvClient.GetKeyAsync(KeyName);

    // 3. Build a local RSA object from the key vault key
    RSA rsa = await BuildRsaFromKeyVaultAsync(kvClient, key);

    // 4. Create signing credentials (RS256 is the most common)
    var signingCredentials = new SigningCredentials(
        new RsaSecurityKey(rsa) { KeyId = key.Id },
        SecurityAlgorithms.RsaSha256);

    // 5. Build the JWT claims (customize as you need)
    var claims = new[]
    {
            new Claim(JwtRegisteredClaimNames.Sub, "user123"),
            new Claim(JwtRegisteredClaimNames.Iss, "my-api"),
            new Claim(JwtRegisteredClaimNames.Aud, "my-client"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

    var now = DateTime.UtcNow;
    var token = new JwtSecurityToken(
        issuer: "my-api",
        audience: "my-client",
        claims: claims,
        notBefore: now,
        expires: now.AddMinutes(30),
        signingCredentials: signingCredentials);

    // 6. Write the token
    var handler = new JwtSecurityTokenHandler();
    return handler.WriteToken(token);
}

// --------------------------------------------------------------------
// Helper: turn a Key Vault RSA key into a System.Security.Cryptography.RSA
// --------------------------------------------------------------------
private static async Task<RSA> BuildRsaFromKeyVaultAsync(KeyClient kvClient, KeyVaultKey kvKey)
{
    // If the key is an RSA key stored in the vault, we can ask the service to sign
    // a known payload and then derive the private key locally.
    // The simplest & most secure way is to use the *CryptographyClient* to sign
    // directly (see the "Sign-via-KeyVault" alternative below). 
    // However, if you really need the RSA object locally (e.g., for offline signing),
    // you must export the private key **only if exportable was set to true** when the key was created.

    if (!kvKey.Properties.Exportable)
        throw new InvalidOperationException("The key is not exportable. Use Sign-via-KeyVault approach.");

    // Download the full key (includes private material)
    KeyVaultKey fullKey = await kvClient.GetKeyAsync(kvKey.Name, kvKey.Properties.Version);

    // The KeyVaultKey.Key property is a JsonWebKey that contains N, E, D, etc.
    JsonWebKey jwk = fullKey.Key;

    var rsa = RSA.Create();
    rsa.KeySize = jwk.N.Length * 8; // rough estimate

    var parameters = new RSAParameters
    {
        Modulus = jwk.N,
        Exponent = jwk.E,
        D = jwk.D,
        P = jwk.P,
        Q = jwk.Q,
        DP = jwk.DP,
        DQ = jwk.DQ,
        InverseQ = jwk.QInv
    };

    rsa.ImportParameters(parameters);
    return rsa;
}
}