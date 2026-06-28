// IdentityHashService.cs
public class IdentityHashService
{
    private readonly byte[] _secretKey;

    public IdentityHashService(IConfiguration config)
    {
        _secretKey = Convert.FromBase64String(
            config["DynatraceTracking:HmacSecret"]!);
    }

    public string ComputeHash(string subscriberId, string businessUserId)
    {
        var input = $"{subscriberId}:{businessUserId}";
        using var hmac = new HMACSHA256(_secretKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
        // First 16 bytes as hex — short enough for a tag, unique enough
        return Convert.ToHexString(hash[..16]).ToLowerInvariant();
    }
}

// Step 2 — Mapping table (Cosmos DB, partitioned by /sponsorId):
// {
//     "id": "a3f9bc12e44d1089",
//   "sponsorId": "sponsor-001",
//   "subscriberId": "sub-abc",          // encrypted at rest
//   "businessUserId": "biz-xyz",        // encrypted at rest  
//   "firstSeen": "2025-01-15T10:23:00Z",
//   "lastSeen": "2025-06-28T08:45:00Z",
//   "visitCount": 47
// }
// Step 3 — Inject hash + visitor_type into the SPA context (your existing SponsorContext or a new TrackingContext):
// TrackingContext — initialized from the /auth/exchange response
// export function initDynatraceIdentity(hash: string, visitorType: 'new' | 'returning') {
//   if (typeof window.dtrum === 'undefined') return;

//   window.dtrum.identifyUser(hash);   // sets the user tag — opaque hash
//   window.dtrum.addSessionProperty('visitor_type', visitorType, true);
//   window.dtrum.sendSessionProperties();
// }