namespace Authly.Authorization.UserStorage
{
    /// <summary>
    /// Interface for creating user storage instances based on configuration
    /// </summary>
    public interface IUserStorageFactory
    {
        /// <summary>
        /// Creates and returns the configured user storage implementation
        /// </summary>
        /// <returns>User storage instance</returns>
        IUserStorage GetUserStorage(); 
    }
}
