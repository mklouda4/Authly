using Authly.Extension;
using Authly.Models;
using Authly.Services;
using System.Text.Json;

namespace Authly.Authorization.UserStorage
{
    /// <summary>
    /// In-memory implementation of user storage with file-based persistence
    /// </summary>
    public class InMemoryUserStorage : UserStorageBase
    {
        private readonly List<User> _users;
        private readonly List<RoleModel> _roles;
        private readonly string _usersFilePath;
        private readonly IApplicationLogger _appLogger;
        private readonly IApplicationService _applicationService;
        private readonly JsonSerializerOptions _jsonSerializerOptions;

        /// <summary>
        /// Initializes a new instance of InMemoryUserStorage
        /// </summary>
        /// <param name="environment">Web host environment for determining file paths</param>
        /// <param name="appLogger">Application logger for debugging and error tracking</param>
        public InMemoryUserStorage(IWebHostEnvironment environment, IApplicationLogger appLogger, IApplicationService applicationService)
        {
            _appLogger = appLogger;
            _applicationService = applicationService;
            _usersFilePath = Path.Combine(environment.WebRootPath ?? environment.ContentRootPath, "data", "users.json");

            // Initialize JsonSerializerOptions once
            _jsonSerializerOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                WriteIndented = true
            };

            // Load existing data or create defaults
            _users = LoadUsersFromFile();
            _roles = [];
        }

        /// <summary>
        /// Loads users from JSON file or creates default users if file doesn't exist
        /// </summary>
        /// <returns>List of users loaded from file or default users</returns>
        private List<User> LoadUsersFromFile()
        {
            try
            {
                // Create directory if it doesn't exist
                var directory = Path.GetDirectoryName(_usersFilePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                if (File.Exists(_usersFilePath))
                {
                    var json = File.ReadAllText(_usersFilePath);
                    var users = JsonSerializer.Deserialize<List<User>>(json, _jsonSerializerOptions);

                    foreach (var user in users ?? [])
                    {
                        user.Id = user.UserName.GetDeterministicStringFromString();
                        user.NormalizedUserName = user.UserName?.ToUpper();
                        user.Email ??= $"{user.UserName?.ToLower()}@{_applicationService.ApplicationName}.com".ToLower();
                        user.NormalizedEmail = user.Email?.ToUpper() ?? string.Empty;
                        user.SecurityStamp = $"{user.UserName}-security-stamp".ToLower();
                        user.EmailConfirmed = true;
                    }

                    if (users != null && users.Count > 0)
                    {
                        _appLogger.Log("InMemoryUserStorage", $"Loaded {users.Count} users from file");
                        return users;
                    }
                }
            }
            catch (Exception ex)
            {
                _appLogger.LogError("InMemoryUserStorage", $"Failed to load users from file: {ex.Message}", ex);
            }

            var defaultUsers = new List<User>
            {
                new() {
                    Id = "admin".GetDeterministicStringFromString(),
                    UserName = "admin",
                    NormalizedUserName = "ADMIN",
                    PasswordHash = "admin123",
                    Email = "admin@authly.com",
                    NormalizedEmail = "ADMIN@AUTHLY.COM",
                    FullName = "Administrator",
                    HasTotp = false,
                    TotpSecret = null,
                    SecurityStamp = "admin-security-stamp",
                    EmailConfirmed = true,
                    Administrator = true
                },
                new() {
                    Id = "user".GetDeterministicStringFromString(),
                    UserName = "user",
                    NormalizedUserName = "USER",
                    PasswordHash = "user123",
                    Email = "user@authly.com",
                    NormalizedEmail = "USER@AUTHLY.COM",
                    FullName = "Test User",
                    HasTotp = false,
                    SecurityStamp = "user-security-stamp",
                    EmailConfirmed = true,
                    Administrator = false
                }
            };

            SaveUsersToFile(defaultUsers);
            _appLogger.Log("InMemoryUserStorage", $"Created {defaultUsers.Count} default users");
            return defaultUsers;
        }

        private void SaveUsersToFile(List<User> users)
        {
            try
            {
                var toSave = new List<SaveUserModel>();

                foreach (var user in users)
                {
                    toSave.Add(new SaveUserModel
                    {
                        UserName = user.UserName!,
                        Email = user.Email!,
                        Password = user.Password,
                        FullName = user.FullName,
                        HasTotp = user.HasTotp,
                        TotpSecret = user.TotpSecret,
                        FailedLoginAttempts = user.FailedLoginAttempts,
                        LastFailedLoginAttempt = user.LastFailedLoginAttempt,
                        LockoutStart = user.LockoutStart,
                        LockoutEnd = user.LockoutEnd,
                        Administrator = user.Administrator,
                        IsExternal = user.IsExternal
                    });
                }

                var json = JsonSerializer.Serialize(toSave, _jsonSerializerOptions);
                File.WriteAllText(_usersFilePath, json);
                _appLogger.Log("InMemoryUserStorage", $"Saved {users.Count} users to file");
            }
            catch (Exception ex)
            {
                _appLogger.LogError("InMemoryUserStorage", $"Failed to save users to file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Finds a user by their unique identifier
        /// </summary>
        public override async Task<User?> FindUserById(string userId)
        {
            await Task.CompletedTask;
            return _users.FirstOrDefault(x => x.Id == userId);
        }

        /// <summary>
        /// Finds a user by their username (case-insensitive)
        /// </summary>
        public override async Task<User?> FindUserByName(string username)
        {
            await Task.CompletedTask;
            return _users.FirstOrDefault(x => 
                string.Equals(x.UserName, username, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(x.NormalizedUserName, username.ToUpper(), StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Finds a user by their email address (case-insensitive)
        /// </summary>
        public override async Task<User?> FindUserByEmail(string email)
        {
            await Task.CompletedTask;
            return _users.FirstOrDefault(x => 
                string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(x.NormalizedEmail, email.ToUpper(), StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Finds first user
        /// </summary>
        public override async Task<User?> FindFirst()
        {
            await Task.CompletedTask;
            return _users.FirstOrDefault();
        }

        /// <summary>
        /// Finds a role by its unique identifier
        /// </summary>
        public override async Task<RoleModel?> FindRoleById(string roleId)
        {
            await Task.CompletedTask;
            return _roles.FirstOrDefault(x => x.Id == roleId);
        }

        /// <summary>
        /// Finds a role by its name/code (case-insensitive)
        /// </summary>
        public override async Task<RoleModel?> FindRoleByName(string roleName)
        {
            await Task.CompletedTask;
            return _roles.FirstOrDefault(x => 
                string.Equals(x.Code, roleName, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Gets all roles assigned to a specific user (currently returns default roles for admin)
        /// </summary>
        public override async Task<List<RoleModel>> GetUserRoles(string userId)
        {
            await Task.CompletedTask;
            
            // Simple role assignment logic for demo purposes
            var user = _users.FirstOrDefault(x => x.Id == userId);
            var roles = new List<RoleModel>();
            if (user?.Administrator == true)
            {
                roles.Add(new("AD1", "administrator"));
                roles.Add(new("AD2", "admin"));
            }
            roles.Add(new("US1", "user"));

            return roles;
        }

        /// <summary>
        /// Validates user credentials for authentication
        /// </summary>
        public override async Task<User?> ValidateUserAccess(LoginModel loginModel)
        {
            await Task.CompletedTask;
            
            return _users.FirstOrDefault(x => 
                (string.Equals(x.UserName, loginModel.Username, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(x.Email, loginModel.Username, StringComparison.OrdinalIgnoreCase)) &&
                x.PasswordHash == loginModel.Password);
        }

        /// <summary>
        /// Validates user credentials for authentication with security checks
        /// NOTE: This method is kept for backwards compatibility but is deprecated
        /// Use SecurityService for security checks instead
        /// </summary>
        public override async Task<AuthenticationResult> ValidateUserAccessWithSecurity(LoginModel loginModel, string ipAddress)
        {
            await Task.CompletedTask;
            
            try
            {
                _appLogger.Log("InMemoryUserStorage", $"Validating user access for {loginModel.Username} from IP {ipAddress}");
                
                // First, find the user
                var user = _users.FirstOrDefault(x => 
                    (string.Equals(x.UserName, loginModel.Username, StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(x.Email, loginModel.Username, StringComparison.OrdinalIgnoreCase)));

                if (user == null)
                {
                    _appLogger.LogWarning("InMemoryUserStorage", $"User {loginModel.Username} not found");
                    return AuthenticationResult.FailedResult("Invalid username or password");
                }

                // Check if user is locked out
                if (user.IsLockedOut)
                {
                    _appLogger.LogWarning("InMemoryUserStorage", $"User {loginModel.Username} is locked out until {user.LockoutEnd}");
                    return AuthenticationResult.LockedOutResult(user.LockoutEnd!.Value);
                }

                // Validate password
                if (user.PasswordHash != loginModel.Password)
                {
                    _appLogger.LogWarning("InMemoryUserStorage", $"Invalid password for user {loginModel.Username}");
                    return AuthenticationResult.FailedResult("Invalid username or password");
                }

                // If we get here, credentials are valid
                _appLogger.Log("InMemoryUserStorage", $"User {loginModel.Username} authenticated successfully");
                return AuthenticationResult.SuccessResult(user);
            }
            catch (Exception ex)
            {
                _appLogger.LogError("InMemoryUserStorage", $"Error during user validation: {ex.Message}", ex);
                return AuthenticationResult.FailedResult("Authentication error occurred");
            }
        }

        /// <summary>
        /// Updates an existing user's information and saves to file
        /// </summary>
        public override async Task<bool> UpdateUser(User user)
        {
            await Task.CompletedTask;
            
            try
            {
                var existingUser = _users.FirstOrDefault(x => x.Id == user.Id);
                if (existingUser != null)
                {
                    // Update existing user properties
                    existingUser.FullName = user.FullName;
                    existingUser.Email = user.Email;
                    existingUser.NormalizedEmail = user.NormalizedEmail;
                    existingUser.HasTotp = user.HasTotp;
                    existingUser.TotpSecret = user.TotpSecret;
                    existingUser.FailedLoginAttempts = user.FailedLoginAttempts;
                    existingUser.LastFailedLoginAttempt = user.LastFailedLoginAttempt;
                    existingUser.LockoutStart = user.LockoutStart;
                    existingUser.LockoutEnd = user.LockoutEnd;
                    existingUser.Administrator = user.Administrator;
                    existingUser.IsExternal = user.IsExternal;

                    if (!string.IsNullOrEmpty(user.PasswordHash))
                    {
                        existingUser.PasswordHash = user.PasswordHash;
                    }
                    
                    // Save updated users to file
                    SaveUsersToFile(_users);
                    _appLogger.Log("InMemoryUserStorage", $"Updated user {user.Id} successfully");
                    return true;
                }
                
                _appLogger.LogWarning("InMemoryUserStorage", $"User {user.Id} not found for update");
                return false;
            }
            catch (Exception ex)
            {
                _appLogger.LogError("InMemoryUserStorage", $"Failed to update user {user.Id}: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Creates a new user
        /// </summary>
        public override async Task<bool> CreateUser(User user)
        {
            await Task.CompletedTask;
            
            try
            {
                // Check if user already exists
                var existingUser = _users.FirstOrDefault(x => 
                    string.Equals(x.UserName, user.UserName, StringComparison.OrdinalIgnoreCase));
                
                if (existingUser != null)
                {
                    _appLogger.LogWarning("InMemoryUserStorage", $"User with username {user.UserName} or email {user.Email} already exists");
                    return false;
                }
                
                // Generate new ID
                user.Id = (_users.Count + 1).ToString();
                user.NormalizedUserName = user.UserName?.ToUpper();
                user.NormalizedEmail = user.Email?.ToUpper();
                user.SecurityStamp = $"{user.UserName}-security-stamp".ToLower();
                user.EmailConfirmed = true;
                
                _users.Add(user);
                SaveUsersToFile(_users);
                
                _appLogger.Log("InMemoryUserStorage", $"Created user {user.Id} successfully");
                return true;
            }
            catch (Exception ex)
            {
                _appLogger.LogError("InMemoryUserStorage", $"Failed to create user: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Deletes a user
        /// </summary>
        public override async Task<bool> DeleteUser(string userId)
        {
            await Task.CompletedTask;
            
            try
            {
                var user = _users.FirstOrDefault(x => x.Id == userId);
                if (user != null)
                {
                    _users.Remove(user);
                    SaveUsersToFile(_users);
                    _appLogger.Log("InMemoryUserStorage", $"Deleted user {userId} successfully");
                    return true;
                }
                
                _appLogger.LogWarning("InMemoryUserStorage", $"User {userId} not found for deletion");
                return false;
            }
            catch (Exception ex)
            {
                _appLogger.LogError("InMemoryUserStorage", $"Failed to delete user {userId}: {ex.Message}", ex);
                return false;
            }
        }

        /// <summary>
        /// Gets all users in the system
        /// </summary>
        public override async Task<List<User>> GetAllUsers()
        {
            await Task.CompletedTask;
            return [.. _users];
        }
    }
}
