// In verifier service
var keyClient = new KeyClient(new Uri(vaultUri), new DefaultAzureCredential());
var key = keyClient.GetKey(keyName);
var publicRsa = new RsaSecurityKey(key.Value.Key.ToRsaPublicKey()); // Exports public key only

var validationParams = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = publicRsa,
    ValidIssuer = "https://myapp.com",
    ValidAudience = "https://api.myapp.com",
    ValidateLifetime = true,
    ClockSkew = TimeSpan.Zero
};

var handler = new JwtSecurityTokenHandler();
var principal = handler.ValidateToken(token, validationParams, out _);