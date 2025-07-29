using Authly.Authorization.UserStorage;
using Authly.Extension;
using Authly.Models;
using Authly.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace Authly.Authorization
{
    /// <summary>
    /// Custom user store implementation for ASP.NET Core Identity integration
    /// </summary>
    public class CustomUserStore(IUserStorage userManagement) : IUserStore<User>
    {
        /// <summary>
        /// Creates a new user (not implemented - returns success)
        /// </summary>
        public Task<IdentityResult> CreateAsync(User user, CancellationToken cancellationToken)
            => IdentityResult.Success.ToTaskResult();

        /// <summary>
        /// Deletes a user (not implemented - returns success)
        /// </summary>
        public Task<IdentityResult> DeleteAsync(User user, CancellationToken cancellationToken)
            => IdentityResult.Success.ToTaskResult();

        /// <summary>
        /// Disposes resources
        /// </summary>
        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finds a user by their unique identifier
        /// </summary>
        public async Task<User?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var user = await userManagement.FindUserById(userId);
            return user;
        }

        /// <summary>
        /// Finds a user by their normalized username
        /// </summary>
        public async Task<User?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var user = await userManagement.FindUserByName(normalizedUserName);
            return user;
        }

        /// <summary>
        /// Gets the normalized username for a user
        /// </summary>
        public Task<string?> GetNormalizedUserNameAsync(User user, CancellationToken cancellationToken)
            => Task.FromResult(user?.NormalizedUserName ?? user?.UserName?.ToUpper());

        /// <summary>
        /// Gets the user ID
        /// </summary>
        public Task<string> GetUserIdAsync(User user, CancellationToken cancellationToken)
            => Task.FromResult(user?.Id ?? string.Empty);

        /// <summary>
        /// Gets the username
        /// </summary>
        public Task<string?> GetUserNameAsync(User user, CancellationToken cancellationToken)
            => Task.FromResult(user?.UserName);

        /// <summary>
        /// Sets the normalized username
        /// </summary>
        public Task SetNormalizedUserNameAsync(User user, string? normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the username
        /// </summary>
        public Task SetUserNameAsync(User user, string? userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates a user in the storage
        /// </summary>
        public Task<IdentityResult> UpdateAsync(User user, CancellationToken cancellationToken)
        {
            // If we have InMemoryUserStorage, attempt to save changes
            if (userManagement is InMemoryUserStorage inMemoryStorage)
            {
                var updateTask = inMemoryStorage.UpdateUser(user);
                // Wait for update operation to complete
                updateTask.Wait(cancellationToken);
            }
            
            return Task.FromResult(IdentityResult.Success);
        }
    }

    /// <summary>
    /// Custom role store implementation for ASP.NET Core Identity integration
    /// </summary>
    public class CustomRoleStore(IUserStorage userManagement) : IRoleStore<IdentityRole>
    {
        /// <summary>
        /// Creates a new role (not implemented - returns success)
        /// </summary>
        public Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken)
            => IdentityResult.Success.ToTaskResult();

        /// <summary>
        /// Deletes a role (not implemented - returns success)
        /// </summary>
        public Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken)
            => IdentityResult.Success.ToTaskResult();

        /// <summary>
        /// Disposes resources
        /// </summary>
        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Finds a role by its unique identifier
        /// </summary>
        public async Task<IdentityRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            var role = await userManagement.FindRoleById(roleId);
            
            if (role == null)
                return null;

            return new IdentityRole()
            {
                Id = role.Id ?? string.Empty,
                Name = role.Code,
                NormalizedName = role.Code?.ToUpper()
            };
        }
        
        /// <summary>
        /// Finds a role by its normalized name
        /// </summary>
        public async Task<IdentityRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            var role = await userManagement.FindRoleByName(normalizedRoleName);
            
            if (role == null)
                return null;

            return new IdentityRole()
            {
                Id = role.Id ?? string.Empty,
                Name = role.Code,
                NormalizedName = role.Code?.ToUpper()
            };
        }

        /// <summary>
        /// Gets the normalized role name
        /// </summary>
        public Task<string?> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
            => Task.FromResult(role?.NormalizedName ?? role?.Name?.ToUpper());

        /// <summary>
        /// Gets the role ID
        /// </summary>
        public Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken cancellationToken)
            => Task.FromResult(role?.Id ?? string.Empty);

        /// <summary>
        /// Gets the role name
        /// </summary>
        public Task<string?> GetRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
            => Task.FromResult(role?.Name);

        /// <summary>
        /// Sets the normalized role name
        /// </summary>
        public Task SetNormalizedRoleNameAsync(IdentityRole role, string? normalizedName, CancellationToken cancellationToken)
        {
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the role name
        /// </summary>
        public Task SetRoleNameAsync(IdentityRole role, string? roleName, CancellationToken cancellationToken)
        {
            role.Name = roleName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates a role (not implemented - returns success)
        /// </summary>
        public Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken)
            => IdentityResult.Success.ToTaskResult();
    }

    /// <summary>
    /// Custom sign-in manager implementation with custom authentication logic
    /// </summary>
    public class CustomSignInManager(
        UserManager<User> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<User> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<User>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<User> confirmation,
        IUserStorage userManagement,
        IMqttService mqttService
        )
        : SignInManager<User>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
        private const string scheme = "Identity.Application";

        public Task<AuthenticateResult> AuthenticateAsync()
            => Context.AuthenticateAsync(scheme);

        /// <summary>
        /// Signs in a user with custom claims creation
        /// </summary>
        public override async Task SignInAsync(User user, bool isPersistent, string? authenticationMethod = null)
        {
            var principal = await CreateUserPrincipalAsync(user);

            // Sign in user and set authentication cookie
            await Context.SignInAsync(
                scheme,
                principal,
                new AuthenticationProperties() { IsPersistent = isPersistent });
        }

        /// <summary>
        /// Attempts to sign in a user with username and password
        /// </summary>
        public override async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            var loginModel = new LoginModel() { Username = userName, Password = password };
            var user = await userManagement.ValidateUserAccess(loginModel);
            if (user?.Id == null)
                return SignInResult.Failed;

            var principal = await CreateUserPrincipalAsync(user);

            // Sign in user and set authentication cookie
            await Context.SignInAsync(
                scheme,
                principal,
                new AuthenticationProperties() { IsPersistent = isPersistent });

            await PublishEvent("authly/signin", user);

            return SignInResult.Success;
        }
        
        /// <summary>
        /// Signs out the current user
        /// </summary>
        public override async Task SignOutAsync()
        {
            await PublishEvent("authly/signout", GetUserFromPrincipal(Context));

            // Sign out user and remove authentication cookie
            await Context.SignOutAsync(scheme);
            await base.SignOutAsync();
        }
        
        /// <summary>
        /// Checks if a principal is signed in
        /// </summary>
        public override bool IsSignedIn(ClaimsPrincipal principal)
            => principal.Identity?.IsAuthenticated ?? false;
            
        /// <summary>
        /// Validates the security stamp for a principal
        /// </summary>
        public override Task<User?> ValidateSecurityStampAsync(ClaimsPrincipal? principal)
        {
            return base.ValidateSecurityStampAsync(principal);
        }
        
        /// <summary>
        /// Creates a claims principal for a user with custom claims
        /// </summary>
        public override async Task<ClaimsPrincipal> CreateUserPrincipalAsync(User user)
        {
            var userData = await userManagement.FindUserById(user.Id);            
            if (userData == null)
                return new ClaimsPrincipal();
                
            var claims = new List<Claim>
            {
                new(ClaimTypes.UserData, userData.Id ?? string.Empty),
                new(ClaimTypes.Name, userData.FullName ?? userData.UserName ?? string.Empty),
                new(ClaimTypes.NameIdentifier, userData.UserName ?? string.Empty),
                new(ClaimTypes.Email, userData.Email ?? string.Empty),
                new(Options.ClaimsIdentity.SecurityStampClaimType, userData.SecurityStamp ?? string.Empty),
                new("HasTotp", userData.HasTotp.ToString() ?? "false")
            };

            // Add role claims
            var roles = await userManagement.GetUserRoles(userData.Id ?? string.Empty);
            foreach (var role in roles ?? [])
            {
                if (!claims.Any(x => x.Type == ClaimTypes.Role && x.Value == role.Code))
                    claims.Add(new(ClaimTypes.Role, role.Code ?? string.Empty));
            }

            var identity = new ClaimsIdentity(claims, scheme);
            var principal = new ClaimsPrincipal(identity);

            return principal;
        }

        private Models.User GetUserFromPrincipal(HttpContext context)
        {
            var claims = (context?.User?.Claims?.ToList() ?? []);
            var user = new Models.User()
            {
                Id = claims?.FirstOrDefault(c => c.Type == ClaimTypes.UserData)?.Value,
                UserName = claims?.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value,
                FullName = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? string.Empty,
                Email = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                HasTotp = claims?.FirstOrDefault(c => c.Type == "HasTotp")?.Value == "true",
            };
            return user;
        }

        private async Task PublishEvent(string topic, Models.User user)
        {
            await mqttService.PublishAsync(topic, new { userId = user?.Id, userName = user?.UserName, name = user?.FullName, email = user?.Email, timestamp = DateTime.UtcNow });
        }
    }

    /// <summary>
    /// Custom user manager implementation with enhanced user management capabilities
    /// </summary>
    public class CustomUserManager(
        IUserStore<User> store,
        IOptions<IdentityOptions> optionsAccessor,
        IPasswordHasher<User> passwordHasher,
        IEnumerable<IUserValidator<User>> userValidators,
        IEnumerable<IPasswordValidator<User>> passwordValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<User>> logger,
        IUserStorage userManagement
        )
        : UserManager<User>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
    {
        /// <summary>
        /// Indicates that this user manager supports security stamps
        /// </summary>
        public override bool SupportsUserSecurityStamp => true;

        /// <summary>
        /// Gets a user from a claims principal
        /// </summary>
        public override async Task<User?> GetUserAsync(ClaimsPrincipal principal)
        {
            var userId = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.UserData)?.Value;
            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrWhiteSpace(userId))
                return await Store.FindByIdAsync(userId, CancellationToken.None);
                
            var username = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrWhiteSpace(username))
                return await Store.FindByNameAsync(username.ToUpper(), CancellationToken.None);

            return null;
        }
        
        /// <summary>
        /// Gets the roles assigned to a user
        /// </summary>
        public override async Task<IList<string>> GetRolesAsync(User user)
        {
            var roles = await userManagement.GetUserRoles(user.Id);
            return roles?.Select(x => x.Code ?? string.Empty)?.ToList() ?? [];
        }

        /// <summary>
        /// Verifies a user's password
        /// </summary>
        public override async Task<bool> CheckPasswordAsync(User user, string password)
        {
            var loginModel = new LoginModel() { Username = user.UserName ?? string.Empty, Password = password };
            var userData = await userManagement.ValidateUserAccess(loginModel);
            return userData?.Id != null;
        }
        
        /// <summary>
        /// Updates the security stamp for a user
        /// </summary>
        public override Task<IdentityResult> UpdateSecurityStampAsync(User user)
        {
            user.SecurityStamp = Guid.NewGuid().ToString();
            return Task.FromResult(IdentityResult.Success);
        }
        
        /// <summary>
        /// Gets the security stamp for a user
        /// </summary>
        public override Task<string> GetSecurityStampAsync(User user)
        {
            return Task.FromResult(user?.SecurityStamp ?? string.Empty);
        }
    }
}
