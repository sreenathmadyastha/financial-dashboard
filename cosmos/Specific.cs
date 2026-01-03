// Product with partition keys and IsCloverLinked
public class Product : PartitionedEntity
{
    [JsonProperty("name")]
    public string Name { get; set; }

    [JsonProperty("description")]
    public string Description { get; set; }

    [JsonProperty("price")]
    public decimal Price { get; set; }

    [JsonProperty("category")]
    public string Category { get; set; }

    [JsonProperty("isCloverLinked")]
    public bool IsCloverLinked { get; set; }

    [JsonProperty("sku")]
    public string Sku { get; set; }
}

// Order with partition keys but no IsCloverLinked
public class Order : PartitionedEntity
{
    [JsonProperty("orderNumber")]
    public string OrderNumber { get; set; }

    [JsonProperty("customerId")]
    public string CustomerId { get; set; }

    [JsonProperty("status")]
    public string Status { get; set; }

    [JsonProperty("totalAmount")]
    public decimal TotalAmount { get; set; }

    [JsonProperty("items")]
    public List<OrderItem> Items { get; set; }
}

// Customer with partition keys
public class Customer : PartitionedEntity
{
    [JsonProperty("name")]
    public string Name { get; set; }

    [JsonProperty("email")]
    public string Email { get; set; }

    [JsonProperty("phone")]
    public string Phone { get; set; }

    [JsonProperty("address")]
    public Address Address { get; set; }

    [JsonProperty("loyaltyPoints")]
    public int LoyaltyPoints { get; set; }
}

// Example: Simple entity with just audit fields (no partition keys)
public class AuditLog : AuditableEntity
{
    [JsonProperty("action")]
    public string Action { get; set; }

    [JsonProperty("entityType")]
    public string EntityType { get; set; }

    [JsonProperty("entityId")]
    public string EntityId { get; set; }

    [JsonProperty("details")]
    public string Details { get; set; }
}

// Example: Entity with different partition key structure
public class GlobalSettings : AuditableEntity
{
    [JsonProperty("tenantId")]
    public string TenantId { get; set; }

    [JsonProperty("settingKey")]
    public string SettingKey { get; set; }

    [JsonProperty("settingValue")]
    public string SettingValue { get; set; }
}