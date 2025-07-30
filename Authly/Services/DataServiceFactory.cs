using Authly.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

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
    /// Custom logger provider for Entity Framework that uses IApplicationLogger
    /// </summary>
    public class EntityFrameworkApplicationLoggerProvider : ILoggerProvider
    {
        private readonly IApplicationLogger _applicationLogger;

        public EntityFrameworkApplicationLoggerProvider(IApplicationLogger applicationLogger)
        {
            _applicationLogger = applicationLogger;
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new EntityFrameworkApplicationLogger(_applicationLogger, categoryName);
        }

        public void Dispose()
        {
            // Nothing to dispose
        }
    }

    /// <summary>
    /// Custom logger for Entity Framework that forwards to IApplicationLogger
    /// </summary>
    public class EntityFrameworkApplicationLogger : ILogger
    {
        private readonly IApplicationLogger _applicationLogger;
        private readonly string _categoryName;

        public EntityFrameworkApplicationLogger(IApplicationLogger applicationLogger, string categoryName)
        {
            _applicationLogger = applicationLogger;
            _categoryName = categoryName;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return new NoOpDisposable();
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return _applicationLogger.IsEnabled;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;

            var message = formatter(state, exception);
            var category = "EntityFramework";

            switch (logLevel)
            {
                case LogLevel.Debug:
                case LogLevel.Trace:
                    _applicationLogger.LogDebug(category, $"[{_categoryName}] {message}");
                    break;
                case LogLevel.Information:
                    _applicationLogger.LogInfo(category, $"[{_categoryName}] {message}");
                    break;
                case LogLevel.Warning:
                    _applicationLogger.LogWarning(category, $"[{_categoryName}] {message}");
                    break;
                case LogLevel.Error:
                case LogLevel.Critical:
                    _applicationLogger.LogError(category, $"[{_categoryName}] {message}", exception);
                    break;
            }
        }

        private class NoOpDisposable : IDisposable
        {
            public void Dispose() { }
        }
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
                _ => serviceProvider.GetRequiredService<DatabaseOAuthClientService>()
            };
        }

        /// <summary>
        /// Creates a token service based on configuration
        /// </summary>
        public ITokenService GetTokenService(IServiceProvider serviceProvider)
        {
            return _storageType switch
            {
                _ => serviceProvider.GetRequiredService<DatabaseTokenService>()
            };
        }

        /// <summary>
        /// Creates a security service based on configuration
        /// </summary>
        public ISecurityService GetSecurityService(IServiceProvider serviceProvider)
        {
            return _storageType switch
            {
                _ => serviceProvider.GetRequiredService<DatabaseSecurityService>()
            };
        }

        /// <summary>
        /// Creates an OAuth authorization service based on configuration
        /// </summary>
        public IOAuthAuthorizationService GetOAuthAuthorizationService(IServiceProvider serviceProvider)
        {
            return _storageType switch
            {
                _ => serviceProvider.GetRequiredService<DatabaseOAuthAuthorizationService>()
            };
        }
    }

    /// <summary>
    /// Simple implementation of IDbContextFactory for singleton registration
    /// </summary>
    public class SimpleDbContextFactory(string connectionString) : IDbContextFactory<AuthlyDbContext>
    {
        public AuthlyDbContext CreateDbContext()
        {
            var optionsBuilder = new DbContextOptionsBuilder<AuthlyDbContext>();
            optionsBuilder.UseSqlite(connectionString);

#if DEBUG
            optionsBuilder.EnableSensitiveDataLogging()
                          .EnableDetailedErrors();
#endif

            return new AuthlyDbContext(optionsBuilder.Options);
        }

        public Task<AuthlyDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(CreateDbContext());
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

            // Register database context with custom logger
            //var connectionString = configuration.GetConnectionString("DefaultConnection") 
            //    ?? "Data Source=wwwroot\\data\\authly.db";
            var environment = services.BuildServiceProvider().GetRequiredService<IWebHostEnvironment>();

            var dbPath = Path.Combine(environment.WebRootPath ?? environment.ContentRootPath, "data", "authly.db");
            var connectionString = $"Data Source={dbPath}";

            // Register regular DbContext for existing services
            services.AddDbContext<AuthlyDbContext>((serviceProvider, options) =>
            {
                options.UseSqlite(connectionString);

#if DEBUG
                // Enable sensitive data logging and detailed errors in debug mode
                options.EnableSensitiveDataLogging()
                       .EnableDetailedErrors();
#endif

                // Configure custom logging for Entity Framework
                var applicationLogger = serviceProvider.GetService<IApplicationLogger>();
                if (applicationLogger != null)
                {
                    var loggerFactory = LoggerFactory.Create(builder =>
                    {
                        builder.AddProvider(new EntityFrameworkApplicationLoggerProvider(applicationLogger));

                        // Set minimum log level for Entity Framework
                        builder.SetMinimumLevel(LogLevel.Information);

                        // Filter specific Entity Framework categories
                        builder.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Information);
                        builder.AddFilter("Microsoft.EntityFrameworkCore.Infrastructure", LogLevel.Warning);
                        builder.AddFilter("Microsoft.EntityFrameworkCore.Model.Validation", LogLevel.Warning);
                    });

                    options.UseLoggerFactory(loggerFactory);
                }
            });

            // Register DbContextFactory manually for MetricsService
            services.AddSingleton<IDbContextFactory<AuthlyDbContext>>(serviceProvider =>
            {
                return new SimpleDbContextFactory(connectionString);
            });

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