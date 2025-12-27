using FastEndpoints;
using Microsoft.AspNetCore.Http;

namespace YourNamespace.Endpoints;

/// <summary>
/// Base endpoint class that provides consistent API response methods
/// </summary>
/// <typeparam name="TRequest">The request DTO type</typeparam>
/// <typeparam name="TResponse">The response DTO type</typeparam>
public abstract class BaseEndpoint<TRequest, TResponse> : Endpoint<TRequest, TResponse>
    where TRequest : notnull
{
    /// <summary>
    /// Sends a successful response with data
    /// </summary>
    protected Task SendOkAsync(TResponse data, string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse<TResponse>.Ok(data, message);
        return SendAsync(response, StatusCodes.Status200OK, ct);
    }

    /// <summary>
    /// Sends a successful response without data
    /// </summary>
    protected Task SendOkAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.Ok(message);
        return SendAsync(response, StatusCodes.Status200OK, ct);
    }

    /// <summary>
    /// Sends a created response with data
    /// </summary>
    protected Task SendCreatedAsync(TResponse data, string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse<TResponse>.Created(data, message);
        return SendAsync(response, StatusCodes.Status201Created, ct);
    }

    /// <summary>
    /// Sends a bad request error response
    /// </summary>
    protected Task SendBadRequestAsync(string message, object? errors = null, CancellationToken ct = default)
    {
        var response = APIResponse.BadRequest(message, errors);
        return SendAsync(response, StatusCodes.Status400BadRequest, ct);
    }

    /// <summary>
    /// Sends a not found error response
    /// </summary>
    protected Task SendNotFoundAsync(string message, CancellationToken ct = default)
    {
        var response = APIResponse.NotFound(message);
        return SendAsync(response, StatusCodes.Status404NotFound, ct);
    }

    /// <summary>
    /// Sends an unauthorized error response
    /// </summary>
    protected Task SendUnauthorizedAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.Unauthorized(message);
        return SendAsync(response, StatusCodes.Status401Unauthorized, ct);
    }

    /// <summary>
    /// Sends a forbidden error response
    /// </summary>
    protected Task SendForbiddenAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.Forbidden(message);
        return SendAsync(response, StatusCodes.Status403Forbidden, ct);
    }

    /// <summary>
    /// Sends an internal server error response
    /// </summary>
    protected Task SendServerErrorAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.ServerError(message);
        return SendAsync(response, StatusCodes.Status500InternalServerError, ct);
    }
}

/// <summary>
/// Base endpoint class for endpoints without a request body
/// </summary>
/// <typeparam name="TResponse">The response DTO type</typeparam>
public abstract class BaseEndpoint<TResponse> : Endpoint<EmptyRequest, TResponse>
{
    /// <summary>
    /// Sends a successful response with data
    /// </summary>
    protected Task SendOkAsync(TResponse data, string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse<TResponse>.Ok(data, message);
        return SendAsync(response, StatusCodes.Status200OK, ct);
    }

    /// <summary>
    /// Sends a successful response without data
    /// </summary>
    protected Task SendOkAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.Ok(message);
        return SendAsync(response, StatusCodes.Status200OK, ct);
    }

    /// <summary>
    /// Sends a bad request error response
    /// </summary>
    protected Task SendBadRequestAsync(string message, object? errors = null, CancellationToken ct = default)
    {
        var response = APIResponse.BadRequest(message, errors);
        return SendAsync(response, StatusCodes.Status400BadRequest, ct);
    }

    /// <summary>
    /// Sends a not found error response
    /// </summary>
    protected Task SendNotFoundAsync(string message, CancellationToken ct = default)
    {
        var response = APIResponse.NotFound(message);
        return SendAsync(response, StatusCodes.Status404NotFound, ct);
    }

    /// <summary>
    /// Sends an unauthorized error response
    /// </summary>
    protected Task SendUnauthorizedAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.Unauthorized(message);
        return SendAsync(response, StatusCodes.Status401Unauthorized, ct);
    }

    /// <summary>
    /// Sends a forbidden error response
    /// </summary>
    protected Task SendForbiddenAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.Forbidden(message);
        return SendAsync(response, StatusCodes.Status403Forbidden, ct);
    }

    /// <summary>
    /// Sends an internal server error response
    /// </summary>
    protected Task SendServerErrorAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.ServerError(message);
        return SendAsync(response, StatusCodes.Status500InternalServerError, ct);
    }
}

/// <summary>
/// Base endpoint class for endpoints without request or response
/// </summary>
public abstract class BaseEndpointWithoutRequest : EndpointWithoutRequest
{
    /// <summary>
    /// Sends a successful response without data
    /// </summary>
    protected Task SendOkAsync(string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse.Ok(message);
        return SendAsync(response, StatusCodes.Status200OK, ct);
    }

    /// <summary>
    /// Sends a successful response with data
    /// </summary>
    protected Task SendOkAsync<T>(T data, string? message = null, CancellationToken ct = default)
    {
        var response = APIResponse<T>.Ok(data, message);
        return SendAsync(response, StatusCodes.Status200OK, ct);
    }

    /// <summary>
    /// Sends a bad request error response
    /// </summary>
    protected Task SendBadRequestAsync(string message, object? errors = null, CancellationToken ct = default)
    {
        var response = APIResponse.BadRequest(message, errors);
        return SendAsync(response, StatusCodes.Status400BadRequest, ct);
    }

    /// <summary>
    /// Sends a not found error response
    /// </summary>
    protected Task SendNotFoundAsync(string message, CancellationToken ct = default)
    {
        var response = APIResponse.NotFound(message);
        return SendAsync(response, StatusCodes.Status404NotFound, ct);
    }
}

// Example usage in an endpoint:
public class GetUserEndpoint : BaseEndpoint<GetUserRequest, UserResponse>
{
    public override void Configure()
    {
        Get("/api/users/{id}");
        AllowAnonymous();
    }

    public override async Task HandleAsync(GetUserRequest req, CancellationToken ct)
    {
        var user = await GetUserFromDatabase(req.Id);

        if (user == null)
        {
            await SendNotFoundAsync("User not found", ct);
            return;
        }

        await SendOkAsync(user, "User retrieved successfully", ct);
    }

    private Task<UserResponse?> GetUserFromDatabase(int id)
    {
        // Your database logic here
        return Task.FromResult<UserResponse?>(null);
    }
}

// Example request/response DTOs
public class GetUserRequest
{
    public int Id { get; set; }
}

public class UserResponse
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}