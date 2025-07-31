using Authly.Models;
using Authly.Authorization.UserStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components;
using OtpNet;
using System.Text;

namespace Authly.Services
{
    /// <summary>
    /// Interface for authentication services including login, logout, and user management
    /// </summary>
    public interface IAuthService
    {
        /// <summary>
        /// Retrieves the currently authenticated user
        /// </summary>
        /// <returns>Current user or null if not authenticated</returns>
        Task<User?> GetCurrentUserAsync();
        
        /// <summary>
        /// Checks if a user requires TOTP for authentication
        /// </summary>
        /// <param name="username">Username to check</param>
        /// <param name="password">Password to validate first</param>
        /// <returns>True if user exists and has TOTP enabled</returns>
        Task<bool> RequiresTotpAsync(string username, string password);
        
        /// <summary>
        /// Updates the current user's profile information
        /// </summary>
        /// <param name="fullName">New full name</param>
        /// <param name="email">New email address</param>
        /// <param name="password">New password (optional)</param>
        /// <param name="hasTotp">Enable/disable TOTP (optional)</param>
        /// <returns>True if update successful, false otherwise</returns>
        Task<bool> UpdateUserAsync(string fullName, string email, string? password = null, bool? hasTotp = null);
        
        /// <summary>
        /// Checks if the current user is authenticated
        /// </summary>
        /// <returns>True if authenticated, false otherwise</returns>
        Task<bool> IsAuthenticatedAsync();
    }

    /// <summary>
    /// Authentication service implementation for user login, logout, and profile management
    /// </summary>
    public class AuthService : IAuthService
    {
        private readonly HttpClient _httpClient;
        private readonly AuthenticationStateProvider _authenticationStateProvider;
        private readonly IUserStorage _userStorage;
        private readonly NavigationManager _navigationManager;
        private readonly IApplicationLogger _logger;

        /// <summary>
        /// Initializes a new instance of AuthService
        /// </summary>
        public AuthService(
            HttpClient httpClient,
            AuthenticationStateProvider authenticationStateProvider,
            IUserStorage userStorage,
            NavigationManager navigationManager,
            IApplicationLogger logger)
        {
            _httpClient = httpClient;
            _authenticationStateProvider = authenticationStateProvider;
            _userStorage = userStorage;
            _navigationManager = navigationManager;
            _logger = logger;
        }

        /// <summary>
        /// Retrieves the currently authenticated user from claims
        /// </summary>
        public async Task<User?> GetCurrentUserAsync()
        {
            try
            {
                var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
                
                if (authState.User?.Identity?.IsAuthenticated == true)
                {
                    var userId = authState.User.FindFirst(ClaimTypes.UserData)?.Value;
                    var userName = authState.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!string.IsNullOrEmpty(userId))
                    {
                        var user = await _userStorage.FindUserById(userId);
                        var userInfo = user == null ? "NULL" : $"{user.UserName} (ID: {user.Id})";
                        _logger.LogDebug("AuthService", $"FindUserById({userId}) returned: {userInfo}");
                        return user;
                    }
                    else if (!string.IsNullOrEmpty(userName))
                    {
                        var user = await _userStorage.FindUserByName(userName);
                        var userInfo = user == null ? "NULL" : $"{user.UserName} (ID: {user.Id})";
                        _logger.LogDebug("AuthService", $"FindUserByName({userName}) returned: {userInfo}");
                        return user;
                    }
                }

                _logger.LogDebug("AuthService", "GetCurrentUserAsync - user not authenticated");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError("AuthService", "Error getting current user", ex);
                return null;
            }
        }

        /// <summary>
        /// Validates credentials and checks if TOTP is required
        /// </summary>
        public async Task<bool> RequiresTotpAsync(string username, string password)
        {
            try
            {
                // Validate basic credentials
                var user = await _userStorage.ValidateUserAccess(new LoginModel { Username = username, Password = password });
                
                // Return true if user exists and has TOTP enabled
                return user != null && user.HasTotp;
            }
            catch (Exception ex)
            {
                _logger.LogError("AuthService", $"Error checking TOTP requirement for user {username}", ex);
                return false;
            }
        }

        /// <summary>
        /// Updates the current user's profile information including TOTP settings
        /// </summary>
        public async Task<bool> UpdateUserAsync(string fullName, string email, string? password = null, bool? hasTotp = null)
        {
            try
            {
                var currentUser = await GetCurrentUserAsync();
                if (currentUser == null)
                {
                    return false;
                }

                // Update user data
                currentUser.FullName = fullName;
                currentUser.Email = email;
                currentUser.NormalizedEmail = email?.ToUpper();

                if (!string.IsNullOrEmpty(password))
                {
                    // In demo implementation we store password as plaintext
                    // In production this should be hashed
                    currentUser.PasswordHash = password;
                }

                if (hasTotp.HasValue)
                {
                    currentUser.HasTotp = hasTotp.Value;
                    
                    if (hasTotp.Value && string.IsNullOrEmpty(currentUser.TotpSecret))
                    {
                        // Generate new TOTP secret
                        var secret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
                        currentUser.TotpSecret = secret;
                    }
                    else if (!hasTotp.Value)
                    {
                        // Clear TOTP secret when disabling
                        currentUser.TotpSecret = null;
                    }
                }

                // Save changes via UserStorage
                var success = await _userStorage.UpdateUser(currentUser);
                if (success)
                {
                    _logger.LogInfo("AuthService", $"User {currentUser.Id} profile updated successfully");
                    return true;
                }
                else
                {
                    _logger.LogWarning("AuthService", $"Failed to update user {currentUser.Id} profile");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("AuthService", "Error updating user profile", ex);
                return false;
            }
        }

        /// <summary>
        /// Checks authentication state via AuthenticationStateProvider
        /// </summary>
        public async Task<bool> IsAuthenticatedAsync()
        {
            try
            {
                var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
                return authState.User?.Identity?.IsAuthenticated == true;
            }
            catch (Exception ex)
            {
                _logger.LogError("AuthService", "Error checking authentication status", ex);
                return false;
            }
        }
    }

    /// <summary>
    /// Response model for login API calls
    /// </summary>
    public class LoginResponse
    {
        /// <summary>
        /// Indicates if login was successful
        /// </summary>
        public bool Success { get; set; }
        
        /// <summary>
        /// Optional message with additional information
        /// </summary>
        public string? Message { get; set; }
        
        /// <summary>
        /// URL to redirect to after successful login
        /// </summary>
        public string? ReturnUrl { get; set; }
    }
}