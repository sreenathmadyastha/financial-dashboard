using FastEndpoints;

var builder = WebApplication.CreateBuilder(args);

// Add FastEndpoints
builder.Services.AddFastEndpoints();

var app = builder.Build();

// Use FastEndpoints
app.UseFastEndpoints(c =>
{
    c.Endpoints.RoutePrefix = "api";
});

Console.WriteLine("API is running with FastEndpoints!");
Console.WriteLine("");
Console.WriteLine("Endpoints:");
Console.WriteLine("  GET  /api/users");
Console.WriteLine("  GET  /api/users/{id}");
Console.WriteLine("  POST /api/users");
Console.WriteLine("  GET  /api/orders");
Console.WriteLine("  GET  /api/orders/{id}");
Console.WriteLine("  POST /api/orders");
Console.WriteLine("");
Console.WriteLine("Example curl command:");
Console.WriteLine("  curl -H \"Authorization: Bearer YOUR_TOKEN_HERE\" http://localhost:5000/api/users");

app.Run();

// ========== Pre-Processor (Filter) for Bearer Token ==========
public class BearerTokenPreProcessor : IGlobalPreProcessor
{
    public Task PreProcessAsync(IPreProcessorContext context, CancellationToken ct)
    {
        var authHeader = context.HttpContext.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrEmpty(authHeader))
        {
            context.HttpContext.Response.StatusCode = 400;
            return context.HttpContext.Response.WriteAsJsonAsync(new { error = "No Authorization header found" }, ct);
        }

        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            context.HttpContext.Response.StatusCode = 400;
            return context.HttpContext.Response.WriteAsJsonAsync(new { error = "Authorization header must start with 'Bearer '" }, ct);
        }

        // Extract the token (everything after "Bearer ")
        var token = authHeader.Substring("Bearer ".Length).Trim();

        // Store token in HttpContext.Items so endpoints can access it
        context.HttpContext.Items["BearerToken"] = token;

        // Log the token (for demo purposes)
        Console.WriteLine($"Bearer Token received: {token}");

        return Task.CompletedTask;
    }
}

// ========== User Endpoints ==========
public class GetAllUsersEndpoint : EndpointWithoutRequest
{
    public override void Configure()
    {
        Get("/users");
        PreProcessor<BearerTokenPreProcessor>();
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var token = HttpContext.Items["BearerToken"]?.ToString();

        await SendAsync(new
        {
            message = "Getting all users",
            receivedToken = token,
            users = new[]
            {
                new { id = 1, name = "John Doe" },
                new { id = 2, name = "Jane Smith" }
            }
        }, cancellation: ct);
    }
}

public class GetUserByIdRequest
{
    public int Id { get; set; }
}

public class GetUserByIdEndpoint : Endpoint<GetUserByIdRequest>
{
    public override void Configure()
    {
        Get("/users/{id}");
        PreProcessor<BearerTokenPreProcessor>();
    }

    public override async Task HandleAsync(GetUserByIdRequest req, CancellationToken ct)
    {
        var token = HttpContext.Items["BearerToken"]?.ToString();

        await SendAsync(new
        {
            message = $"Getting user {req.Id}",
            receivedToken = token,
            user = new { id = req.Id, name = $"User {req.Id}" }
        }, cancellation: ct);
    }
}

public class CreateUserRequest
{
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
}

public class CreateUserEndpoint : Endpoint<CreateUserRequest>
{
    public override void Configure()
    {
        Post("/users");
        PreProcessor<BearerTokenPreProcessor>();
    }

    public override async Task HandleAsync(CreateUserRequest req, CancellationToken ct)
    {
        var token = HttpContext.Items["BearerToken"]?.ToString();

        await SendAsync(new
        {
            message = "User created",
            receivedToken = token,
            userId = 999,
            userName = req.Name,
            userEmail = req.Email
        }, cancellation: ct);
    }
}

// ========== Order Endpoints ==========
public class GetAllOrdersEndpoint : EndpointWithoutRequest
{
    public override void Configure()
    {
        Get("/orders");
        PreProcessor<BearerTokenPreProcessor>();
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var token = HttpContext.Items["BearerToken"]?.ToString();

        await SendAsync(new
        {
            message = "Getting all orders",
            receivedToken = token,
            orders = new[]
            {
                new { id = 101, product = "Laptop", amount = 1200 },
                new { id = 102, product = "Mouse", amount = 25 }
            }
        }, cancellation: ct);
    }
}

public class GetOrderByIdRequest
{
    public int Id { get; set; }
}

public class GetOrderByIdEndpoint : Endpoint<GetOrderByIdRequest>
{
    public override void Configure()
    {
        Get("/orders/{id}");
        PreProcessor<BearerTokenPreProcessor>();
    }

    public override async Task HandleAsync(GetOrderByIdRequest req, CancellationToken ct)
    {
        var token = HttpContext.Items["BearerToken"]?.ToString();

        await SendAsync(new
        {
            message = $"Getting order {req.Id}",
            receivedToken = token,
            order = new { id = req.Id, product = $"Product {req.Id}", amount = 100 }
        }, cancellation: ct);
    }
}

public class CreateOrderRequest
{
    public string Product { get; set; } = string.Empty;
    public decimal Amount { get; set; }
}

public class CreateOrderEndpoint : Endpoint<CreateOrderRequest>
{
    public override void Configure()
    {
        Post("/orders");
        PreProcessor<BearerTokenPreProcessor>();
    }

    public override async Task HandleAsync(CreateOrderRequest req, CancellationToken ct)
    {
        var token = HttpContext.Items["BearerToken"]?.ToString();

        await SendAsync(new
        {
            message = "Order created",
            receivedToken = token,
            orderId = 999,
            product = req.Product,
            amount = req.Amount
        }, cancellation: ct);
    }
}