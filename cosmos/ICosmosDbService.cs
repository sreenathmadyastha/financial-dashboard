public interface ICosmosDbService
{
    // Check and Read operations
    Task<bool> ItemExistsAsync(string id);
    Task<T> GetItemByIdAsync<T>(string id);

    // Create operations
    Task<T> CreateItemAsync<T>(T item);
    Task<T> CreateItemIfNotExistsAsync<T>(T item) where T : IIdentifiable;
    Task<(bool Created, T Item)> TryCreateItemAsync<T>(T item) where T : IIdentifiable;

    // Update operations
    Task<bool> TryUpdateIsCloverLinkedAsync<T>(string id, bool isCloverLinked) where T : ICloverLinkable;
    Task<bool> PatchIsCloverLinkedAsync(string id, bool isCloverLinked);
    Task<T> UpdateItemAsync<T>(string id, T item);

    // Upsert operations
    Task<T> UpsertItemAsync<T>(T item);
    Task<(bool Created, T Item)> CreateOrUpdateIsCloverLinkedAsync<T>(
        string id,
        T newItem,
        bool isCloverLinked) where T : ICloverLinkable, IIdentifiable;

    // Delete operation
    Task<bool> DeleteItemAsync(string id);
}