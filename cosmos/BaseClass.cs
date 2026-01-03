// Pure audit fields only
public abstract class AuditableEntity
{
    [JsonProperty("id")]
    public string Id { get; set; }

    [JsonProperty("createdBy")]
    public string CreatedBy { get; set; }

    [JsonProperty("createdDate")]
    public DateTime CreatedDate { get; set; }

    [JsonProperty("modifiedBy")]
    public string ModifiedBy { get; set; }

    [JsonProperty("modifiedDate")]
    public DateTime ModifiedDate { get; set; }
}

// Optional: Base class for entities that need partition key fields
public abstract class PartitionedEntity : AuditableEntity
{
    [JsonProperty("sponsorId")]
    public string SponsorId { get; set; }

    [JsonProperty("subscriberId")]
    public string SubscriberId { get; set; }

    [JsonProperty("businessUserId")]
    public string BusinessUserId { get; set; }
}