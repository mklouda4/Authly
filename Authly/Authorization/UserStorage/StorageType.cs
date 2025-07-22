namespace Authly.Authorization.UserStorage
{
    /// <summary>
    /// Enumeration of available storage types for user data
    /// </summary>
    public enum StorageType
    {
        /// <summary>
        /// In-memory storage for development and testing
        /// </summary>
        InMemory = 0,
        
        /// <summary>
        /// Database storage for production use
        /// </summary>
        Database = 1,
        
        /// <summary>
        /// API-based external storage
        /// </summary>
        Api = 2
    }
}
