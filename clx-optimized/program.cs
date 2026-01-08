using StackExchange.Redis;
using System.Text.Json;

// Service registration in Program.cs or Startup.cs
public static class ServiceConfiguration
{
    public static IServiceCollection AddClxServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Redis connection
        services.AddSingleton<IConnectionMultiplexer>(sp =>
            ConnectionMultiplexer.Connect(configuration.GetConnectionString("Redis")));

        services.AddSingleton<IClxRedisCache, ClxRedisCache>();
        services.AddHttpClient<IClxApiClient, ClxApiClient>();
        services.AddScoped<IClxDataService, ClxDataService>();

        return services;
    }
}