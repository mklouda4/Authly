using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Authly.Models;
using System.Security.Claims;

namespace Authly.Services
{
    /// <summary>
    /// Authentication state provider for Blazor Server with support for revalidating authentication state
    /// </summary>
    public class IdentityRevalidatingAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
    {
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IdentityOptions _options;

        /// <summary>
        /// Initializes a new instance of IdentityRevalidatingAuthenticationStateProvider
        /// </summary>
        /// <param name="loggerFactory">Logger factory for creating loggers</param>
        /// <param name="scopeFactory">Service scope factory for creating service scopes</param>
        /// <param name="optionsAccessor">Identity options configuration</param>
        public IdentityRevalidatingAuthenticationStateProvider(
            ILoggerFactory loggerFactory,
            IServiceScopeFactory scopeFactory,
            IOptions<IdentityOptions> optionsAccessor)
            : base(loggerFactory)
        {
            _scopeFactory = scopeFactory;
            _options = optionsAccessor.Value;
        }

        /// <summary>
        /// Gets the interval for automatic revalidation of authentication state
        /// </summary>
        protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

        /// <summary>
        /// Validates the current authentication state to ensure user is still valid
        /// </summary>
        /// <param name="authenticationState">Current authentication state to validate</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if authentication state is valid, false otherwise</returns>
        protected override async Task<bool> ValidateAuthenticationStateAsync(
            AuthenticationState authenticationState, CancellationToken cancellationToken)
        {
            // Get user manager from scope to verify user state
            await using var scope = _scopeFactory.CreateAsyncScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            
            // Verify that the user is still valid
            return await ValidateSecurityStampAsync(userManager, authenticationState.User);
        }

        /// <summary>
        /// Validates the security stamp of a user to ensure their authentication is still valid
        /// </summary>
        /// <param name="userManager">User manager for user operations</param>
        /// <param name="principal">Claims principal to validate</param>
        /// <returns>True if security stamp is valid, false otherwise</returns>
        private async Task<bool> ValidateSecurityStampAsync(UserManager<User> userManager, ClaimsPrincipal principal)
        {
            var user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                return false;
            }
            else if (!userManager.SupportsUserSecurityStamp)
            {
                return true;
            }
            else
            {
                var principalStamp = principal.FindFirstValue(_options.ClaimsIdentity.SecurityStampClaimType);
                var userStamp = await userManager.GetSecurityStampAsync(user);
                return principalStamp == userStamp;
            }
        }

        /// <summary>
        /// Forces immediate revalidation of the authentication state
        /// </summary>
        public void RevalidateAuthenticationState()
        {
            // Forces immediate revalidation of authentication state
            Task.Run(async () =>
            {
                var authenticationState = await GetAuthenticationStateAsync();
                NotifyAuthenticationStateChanged(Task.FromResult(authenticationState));
            });
        }
    }
}