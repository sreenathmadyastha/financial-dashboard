public abstract class CosmosDbServiceBase<T> where T : AuditableEntity
{
    protected readonly Container _container;
    protected readonly IUserContextAccessor _userContextAccessor;

    protected CosmosDbServiceBase(
        CosmosClient cosmosClient,
        string databaseName,
        string containerName,
        IUserContextAccessor userContextAccessor)
    {
        _container = cosmosClient.GetContainer(databaseName, containerName);
        _userContextAccessor = userContextAccessor;
    }

    #region Helper Methods

    // Default partition key logic (can be overridden)
    protected virtual PartitionKey GetPartitionKey()
    {
        var userContext = _userContextAccessor.GetUserContext();

        return new PartitionKeyBuilder()
            .Add(userContext.SponsorId)
            .Add(userContext.SubscriberId)
            .Build();
    }

    // For custom partition keys
    protected virtual PartitionKey GetPartitionKeyForItem(T item)
    {
        return GetPartitionKey();
    }

    protected UserContext GetUserContext()
    {
        return _userContextAccessor.GetUserContext();
    }

    // Sets only audit fields
    protected virtual void SetCreatedAuditFields(T item)
    {
        var userContext = GetUserContext();
        var now = DateTime.UtcNow;
        var auditUser = userContext.GetAuditUser();

        item.CreatedBy = auditUser;
        item.CreatedDate = now;
        item.ModifiedBy = auditUser;
        item.ModifiedDate = now;
    }

    // Sets only audit fields
    protected virtual void SetModifiedAuditFields(T item)
    {
        var userContext = GetUserContext();

        item.ModifiedBy = userContext.GetAuditUser();
        item.ModifiedDate = DateTime.UtcNow;
    }

    // Optional: Helper for PartitionedEntity types
    protected virtual void SetPartitionKeyFields(T item)
    {
        if (item is PartitionedEntity partitionedItem)
        {
            var userContext = GetUserContext();

            if (string.IsNullOrEmpty(partitionedItem.SponsorId))
                partitionedItem.SponsorId = userContext.SponsorId;
            if (string.IsNullOrEmpty(partitionedItem.SubscriberId))
                partitionedItem.SubscriberId = userContext.SubscriberId;
            if (string.IsNullOrEmpty(partitionedItem.BusinessUserId))
                partitionedItem.BusinessUserId = userContext.BusinessUserId;
        }
    }

    // Called before create - can be overridden for custom logic
    protected virtual void OnBeforeCreate(T item)
    {
        SetCreatedAuditFields(item);
        SetPartitionKeyFields(item);
    }

    // Called before update - can be overridden for custom logic
    protected virtual void OnBeforeUpdate(T item)
    {
        SetModifiedAuditFields(item);
    }

    #endregion

    #region Read Operations

    public virtual async Task<bool> ExistsAsync(string id)
    {
        try
        {
            var partitionKey = GetPartitionKey();

            await _container.ReadItemAsync<dynamic>(
                id,
                partitionKey,
                new ItemRequestOptions { EnableContentResponseOnWrite = false }
            );

            return true;
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    public virtual async Task<T> GetByIdAsync(string id)
    {
        try
        {
            var partitionKey = GetPartitionKey();
            var response = await _container.ReadItemAsync<T>(id, partitionKey);
            return response.Resource;
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public virtual async Task<IEnumerable<T>> GetAllAsync(string additionalFilter = null)
    {
        var userContext = GetUserContext();

        var queryText = "SELECT * FROM c WHERE c.sponsorId = @sponsorId " +
                       "AND c.subscriberId = @subscriberId";

        if (!string.IsNullOrEmpty(additionalFilter))
        {
            queryText += $" AND ({additionalFilter})";
        }

        var query = new QueryDefinition(queryText)
            .WithParameter("@sponsorId", userContext.SponsorId)
            .WithParameter("@subscriberId", userContext.SubscriberId);

        return await ExecuteQueryAsync(query);
    }

    public virtual async Task<IEnumerable<T>> QueryAsync(QueryDefinition query)
    {
        return await ExecuteQueryAsync(query);
    }

    protected async Task<IEnumerable<T>> ExecuteQueryAsync(QueryDefinition query)
    {
        var iterator = _container.GetItemQueryIterator<T>(query);
        var results = new List<T>();

        while (iterator.HasMoreResults)
        {
            var response = await iterator.ReadNextAsync();
            results.AddRange(response);
        }

        return results;
    }

    #endregion

    #region Create Operations

    public virtual async Task<T> CreateAsync(T item)
    {
        OnBeforeCreate(item);

        var partitionKey = GetPartitionKeyForItem(item);

        try
        {
            var response = await _container.CreateItemAsync(item, partitionKey);
            return response.Resource;
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            throw new ConflictException($"Item with id {item.Id} already exists");
        }
    }

    public virtual async Task<T> CreateIfNotExistsAsync(T item)
    {
        var exists = await ExistsAsync(item.Id);

        if (exists)
        {
            throw new ConflictException($"Item with id {item.Id} already exists");
        }

        return await CreateAsync(item);
    }

    public virtual async Task<(bool Created, T Item)> TryCreateAsync(T item)
    {
        OnBeforeCreate(item);

        var partitionKey = GetPartitionKeyForItem(item);

        try
        {
            var response = await _container.CreateItemAsync(item, partitionKey);
            return (true, response.Resource);
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Conflict)
        {
            var existingItem = await GetByIdAsync(item.Id);
            return (false, existingItem);
        }
    }

    #endregion

    #region Update Operations

    public virtual async Task<T> UpdateAsync(string id, T item)
    {
        OnBeforeUpdate(item);

        var partitionKey = GetPartitionKeyForItem(item);
        var response = await _container.ReplaceItemAsync(item, id, partitionKey);
        return response.Resource;
    }

    public virtual async Task<bool> PatchFieldsAsync(string id, Dictionary<string, object> fieldsToUpdate)
    {
        try
        {
            var userContext = GetUserContext();
            var partitionKey = GetPartitionKey();

            var patchOperations = new List<PatchOperation>();

            foreach (var field in fieldsToUpdate)
            {
                patchOperations.Add(PatchOperation.Set($"/{field.Key}", field.Value));
            }

            patchOperations.Add(PatchOperation.Set("/modifiedBy", userContext.GetAuditUser()));
            patchOperations.Add(PatchOperation.Set("/modifiedDate", DateTime.UtcNow));

            await _container.PatchItemAsync<T>(id, partitionKey, patchOperations);

            return true;
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    #endregion

    #region Upsert Operations

    public virtual async Task<T> UpsertAsync(T item)
    {
        var exists = await ExistsAsync(item.Id);

        if (exists)
        {
            OnBeforeUpdate(item);
        }
        else
        {
            OnBeforeCreate(item);
        }

        var partitionKey = GetPartitionKeyForItem(item);
        var response = await _container.UpsertItemAsync(item, partitionKey);
        return response.Resource;
    }

    #endregion

    #region Delete Operations

    public virtual async Task<bool> DeleteAsync(string id)
    {
        try
        {
            var partitionKey = GetPartitionKey();
            await _container.DeleteItemAsync<T>(id, partitionKey);
            return true;
        }
        catch (CosmosException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return false;
        }
    }

    public virtual async Task<int> DeleteManyAsync(IEnumerable<string> ids)
    {
        var deletedCount = 0;

        foreach (var id in ids)
        {
            var deleted = await DeleteAsync(id);
            if (deleted) deletedCount++;
        }

        return deletedCount;
    }

    #endregion
}