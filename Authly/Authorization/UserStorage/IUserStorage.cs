using Authly.Models;

namespace Authly.Authorization.UserStorage
{
    /// <summary>
    /// Interface for user and role data storage operations
    /// </summary>
    public interface IUserStorage
    {
        /// <summary>
        /// Finds a user by their unique identifier
        /// </summary>
        /// <param name="userId">User ID to search for</param>
        /// <returns>User if found, null otherwise</returns>
        Task<User?> FindUserById(string userId);
        
        /// <summary>
        /// Finds a user by their username
        /// </summary>
        /// <param name="username">Username to search for</param>
        /// <returns>User if found, null otherwise</returns>
        Task<User?> FindUserByName(string username);
        
        /// <summary>
        /// Finds a user by their email address
        /// </summary>
        /// <param name="email">Email address to search for</param>
        /// <returns>User if found, null otherwise</returns>
        Task<User?> FindUserByEmail(string email);
        
        /// <summary>
        /// Creates a new user in the storage
        /// </summary>
        /// <param name="user">User to create</param>
        /// <returns>True if creation successful, false otherwise</returns>
        Task<bool> CreateUser(User user);
        
        /// <summary>
        /// Finds a role by its unique identifier
        /// </summary>
        /// <param name="roleId">Role ID to search for</param>
        /// <returns>Role if found, null otherwise</returns>
        Task<RoleModel?> FindRoleById(string roleId);
        
        /// <summary>
        /// Finds a role by its name
        /// </summary>
        /// <param name="roleName">Role name to search for</param>
        /// <returns>Role if found, null otherwise</returns>
        Task<RoleModel?> FindRoleByName(string roleName);
        
        /// <summary>
        /// Gets all roles assigned to a specific user
        /// </summary>
        /// <param name="userId">User ID to get roles for</param>
        /// <returns>List of user's roles</returns>
        Task<List<RoleModel>> GetUserRoles(string userId);
        
        /// <summary>
        /// Validates user credentials for authentication
        /// </summary>
        /// <param name="loginModel">Login credentials to validate</param>
        /// <returns>User if credentials are valid, null otherwise</returns>
        Task<User?> ValidateUserAccess(LoginModel loginModel);

        /// <summary>
        /// Validates user credentials for authentication with security checks
        /// </summary>
        /// <param name="loginModel">Login credentials to validate</param>
        /// <param name="ipAddress">IP address of the login attempt</param>
        /// <returns>Authentication result with security information</returns>
        Task<AuthenticationResult> ValidateUserAccessWithSecurity(LoginModel loginModel, string ipAddress);
        
        /// <summary>
        /// Updates an existing user's information
        /// </summary>
        /// <param name="user">User with updated information</param>
        /// <returns>True if update successful, false otherwise</returns>
        Task<bool> UpdateUser(User user);

        /// <summary>
        /// Finds first user
        /// </summary>
        /// <returns>Return first user if exists, null otherwise</returns>
        Task<User?> FindFirst();

        /// <summary>
        /// Gets all users in the system
        /// </summary>
        /// <returns>List of all users</returns>
        Task<List<User>> GetAllUsers();
    }
}