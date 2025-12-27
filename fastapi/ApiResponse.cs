using System.Net;

namespace YourNamespace.Models;

/// <summary>
/// Base response class containing common response properties
/// </summary>
/// <typeparam name="T">The type of data being returned</typeparam>
public class BaseResponse<T>
{
    public bool Success { get; set; }
    public HttpStatusCode StatusCode { get; set; }
    public T? Data { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
}

/// <summary>
/// API Response class with factory methods for creating responses
/// </summary>
/// <typeparam name="T">The type of data being returned</typeparam>
public class APIResponse<T> : BaseResponse<T>
{
    /// <summary>
    /// Creates a successful OK response with data
    /// </summary>
    public static APIResponse<T> Ok(T data, string? message = null)
    {
        return new APIResponse<T>
        {
            Success = true,
            StatusCode = HttpStatusCode.OK,
            Data = data,
            ErrorDescription = message
        };
    }

    /// <summary>
    /// Creates a successful Created response with data
    /// </summary>
    public static APIResponse<T> Created(T data, string? message = null)
    {
        return new APIResponse<T>
        {
            Success = true,
            StatusCode = HttpStatusCode.Created,
            Data = data,
            ErrorDescription = message
        };
    }

    /// <summary>
    /// Creates a bad request error response
    /// </summary>
    public static APIResponse<T> BadRequest(string error, string? errorDescription = null)
    {
        return new APIResponse<T>
        {
            Success = false,
            StatusCode = HttpStatusCode.BadRequest,
            Error = error,
            ErrorDescription = errorDescription
        };
    }

    /// <summary>
    /// Creates a failed response with custom status code
    /// </summary>
    public static APIResponse<T> Fail(string error, HttpStatusCode statusCode = HttpStatusCode.InternalServerError, string? errorDescription = null)
    {
        return new APIResponse<T>
        {
            Success = false,
            StatusCode = statusCode,
            Error = error,
            ErrorDescription = errorDescription
        };
    }
}

/// <summary>
/// API Response class without generic type for responses without data
/// </summary>
public class APIResponse : BaseResponse<object>
{
    /// <summary>
    /// Creates a successful OK response without data
    /// </summary>
    public static APIResponse Ok(string? message = null)
    {
        return new APIResponse
        {
            Success = true,
            StatusCode = HttpStatusCode.OK,
            ErrorDescription = message
        };
    }

    /// <summary>
    /// Creates a successful Created response without data
    /// </summary>
    public static APIResponse Created(string? message = null)
    {
        return new APIResponse
        {
            Success = true,
            StatusCode = HttpStatusCode.Created,
            ErrorDescription = message
        };
    }

    /// <summary>
    /// Creates a bad request error response
    /// </summary>
    public static APIResponse BadRequest(string error, string? errorDescription = null)
    {
        return new APIResponse
        {
            Success = false,
            StatusCode = HttpStatusCode.BadRequest,
            Error = error,
            ErrorDescription = errorDescription
        };
    }

    /// <summary>
    /// Creates a not found error response
    /// </summary>
    public static APIResponse NotFound(string error, string? errorDescription = null)
    {
        return new APIResponse
        {
            Success = false,
            StatusCode = HttpStatusCode.NotFound,
            Error = error,
            ErrorDescription = errorDescription
        };
    }

    /// <summary>
    /// Creates an unauthorized error response
    /// </summary>
    public static APIResponse Unauthorized(string? error = null, string? errorDescription = null)
    {
        return new APIResponse
        {
            Success = false,
            StatusCode = HttpStatusCode.Unauthorized,
            Error = error ?? "Unauthorized",
            ErrorDescription = errorDescription
        };
    }

    /// <summary>
    /// Creates a forbidden error response
    /// </summary>
    public static APIResponse Forbidden(string? error = null, string? errorDescription = null)
    {
        return new APIResponse
        {
            Success = false,
            StatusCode = HttpStatusCode.Forbidden,
            Error = error ?? "Forbidden",
            ErrorDescription = errorDescription
        };
    }

    /// <summary>
    /// Creates an internal server error response
    /// </summary>
    public static APIResponse ServerError(string? error = null, string? errorDescription = null)
    {
        return new APIResponse
        {
            Success = false,
            StatusCode = HttpStatusCode.InternalServerError,
            Error = error ?? "Internal Server Error",
            ErrorDescription = errorDescription
        };
    }

    /// <summary>
    /// Creates a failed response with custom status code
    /// </summary>
    public static APIResponse Fail(string error, HttpStatusCode statusCode = HttpStatusCode.InternalServerError, string? errorDescription = null)
    {
        return new APIResponse
        {
            Success = false,
            StatusCode = statusCode,
            Error = error,
            ErrorDescription = errorDescription
        };
    }
}

// Example Usage:
// Success with data
// var response = APIResponse<UserDto>.Ok(userData, "User retrieved successfully");

// Success without data
// var response = APIResponse.Ok("Operation completed successfully");

// Error responses
// var response = APIResponse<UserDto>.BadRequest("Invalid user ID");
// var response = APIResponse.NotFound("User not found");
// var response = APIResponse<UserDto>.Fail("Database connection failed", HttpStatusCode.ServiceUnavailable);