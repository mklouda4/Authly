using Authly.Data;
using Microsoft.EntityFrameworkCore;

namespace Authly.Services
{
    /// <summary>
    /// Data storage types supported by the application
    /// </summary>
    public enum DataStorageType
    {
        JsonFiles,
        Database
    }

    /// <summary>
    /// Factory for creating data service instances based on configuration
    /// </summary>
    public class DataServiceFactory
    {
        private readonly DataStorageType _storageType;

        public DataServiceFactory(IConfiguration configuration)
        {
            //var storageTypeString = configuration["DataStorage:Type"] ?? "Database";

            var storageTypeString = "Database";

            if (!Enum.TryParse<DataStorageType>(storageTypeString, true, out _storageType))
            {
                _storageType = DataStorageType.Database;
            }
        }

        /// <summary>
        /// Gets the configured storage type
        /// </summary>
        public DataStorageType StorageType => _storageType;

        /// <summary>
        /// Creates an OAuth client service based on configuration
        /// </summary>
        public IOAuthClientService GetOAuthClientService(IServiceProvider serviceProvider)
        {
            return _storageType switch
            {
                DataStorageType.Database => serviceProvider.GetRequiredService<DatabaseOAuthClientService>(),
                DataStorageType.JsonFiles => serviceProvider.GetRequiredService<OAuthClientService>(),
                _ => throw new InvalidOperationException($"Unsupported storage type: {_storageType}")
            };
        }

        /// <summary>
        /// Creates a token service based on configuration
        /// </summary>
        public ITokenService GetTokenService(IServiceProvider serviceProvider)
        {
            return _storageType switch
            {
                DataStorageType.Database => serviceProvider.GetRequiredService<DatabaseTokenService>(),
                DataStorageType.JsonFiles => serviceProvider.GetRequiredService<TokenService>(),
                _ => throw new InvalidOperationException($"Unsupported storage type: {_storageType}")
            };
        }

        /// <summary>
        /// Creates a security service based on configuration
        /// </summary>
        public ISecurityService GetSecurityService(IServiceProvider serviceProvider)
        {
            return _storageType switch
            {
                DataStorageType.Database => serviceProvider.GetRequiredService<DatabaseSecurityService>(),
                DataStorageType.JsonFiles => serviceProvider.GetRequiredService<SecurityService>(),
                _ => throw new InvalidOperationException($"Unsupported storage type: {_storageType}")
            };
        }

        /// <summary>
        /// Creates an OAuth authorization service based on configuration
        /// </summary>
        public IOAuthAuthorizationService GetOAuthAuthorizationService(IServiceProvider serviceProvider)
        {
            return _storageType switch
            {
                DataStorageType.Database => serviceProvider.GetRequiredService<DatabaseOAuthAuthorizationService>(),
                DataStorageType.JsonFiles => serviceProvider.GetRequiredService<OAuthAuthorizationService>(),
                _ => throw new InvalidOperationException($"Unsupported storage type: {_storageType}")
            };
        }
    }

    /// <summary>
    /// Extension methods for registering data services
    /// </summary>
    public static class DataServiceExtensions
    {
        public static IServiceCollection AddDataServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Register the factory as singleton (configuration-only)
            services.AddSingleton<DataServiceFactory>();

            // Register database context
            //var connectionString = configuration.GetConnectionString("DefaultConnection") 
            //    ?? "Data Source=wwwroot\\data\\authly.db";

            var connectionString = "Data Source=wwwroot\\data\\authly.db";

            services.AddDbContext<AuthlyDbContext>(options =>
                options.UseSqlite(connectionString));

            // Register all service implementations
            // JSON-based services (existing)
            services.AddScoped<OAuthClientService>();
            services.AddScoped<TokenService>();
            services.AddScoped<SecurityService>();
            services.AddScoped<OAuthAuthorizationService>();

            // Database-based services (new)
            services.AddScoped<DatabaseOAuthClientService>();
            services.AddScoped<DatabaseTokenService>();
            services.AddScoped<DatabaseSecurityService>();
            services.AddScoped<DatabaseOAuthAuthorizationService>();

            // Register factory methods for interface resolution (pass serviceProvider to factory methods)
            services.AddScoped<IOAuthClientService>(provider => 
                provider.GetRequiredService<DataServiceFactory>().GetOAuthClientService(provider));
            
            services.AddScoped<ITokenService>(provider => 
                provider.GetRequiredService<DataServiceFactory>().GetTokenService(provider));
            
            services.AddScoped<ISecurityService>(provider => 
                provider.GetRequiredService<DataServiceFactory>().GetSecurityService(provider));
            
            services.AddScoped<IOAuthAuthorizationService>(provider => 
                provider.GetRequiredService<DataServiceFactory>().GetOAuthAuthorizationService(provider));

            return services;
        }
    }
}