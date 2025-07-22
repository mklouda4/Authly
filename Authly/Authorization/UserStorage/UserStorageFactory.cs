namespace Authly.Authorization.UserStorage
{
    /// <summary>
    /// Factory for creating user storage instances based on application configuration
    /// </summary>
    public class UserStorageFactory : IUserStorageFactory
    {
        private readonly StorageType _storageType;
        private readonly IServiceProvider _serviceProvider;
        
        /// <summary>
        /// Initializes a new instance of UserStorageFactory
        /// </summary>
        /// <param name="configuration">Application configuration</param>
        /// <param name="serviceProvider">Service provider for dependency injection</param>
        public UserStorageFactory(IConfiguration configuration, IServiceProvider serviceProvider)
        {
            _storageType = configuration.GetSection("Auth:Setup").GetValue<StorageType>("Type");
            _serviceProvider = serviceProvider;
        }
        
        /// <summary>
        /// Creates the configured user storage implementation
        /// </summary>
        /// <returns>User storage instance based on configuration</returns>
        /// <exception cref="InvalidOperationException">Thrown when storage type is not properly registered</exception>
        public IUserStorage GetUserStorage()
        {
            return _storageType switch
            {
                StorageType.InMemory => _serviceProvider.GetService<InMemoryUserStorage>() ?? 
                    throw new InvalidOperationException("InMemoryUserStorage not registered."),
                StorageType.Database => throw new NotImplementedException("Database storage not yet implemented."),
                StorageType.Api => throw new NotImplementedException("API storage not yet implemented."),
                _ => _serviceProvider.GetService<InMemoryUserStorage>() ?? 
                    throw new InvalidOperationException("InMemoryUserStorage not registered.")
            };
        }
    }
}
