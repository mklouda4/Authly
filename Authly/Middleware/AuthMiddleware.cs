using Authly.Authorization.Facebook;
using Authly.Authorization.GitHub;
using Authly.Authorization.Google;
using Authly.Authorization.Local;
using Authly.Authorization.Microsoft;

namespace Authly.Middleware
{
    /// <summary>
    /// Authentication middleware that routes HTTP requests to appropriate authentication handlers based on request patterns.
    /// Supports local username/password authentication, Google OAuth with PKCE, and Facebook OAuth authentication.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of AuthMiddleware
    /// </remarks>
    /// <param name="next">Next middleware in the pipeline</param>
    public class AuthMiddleware(RequestDelegate next)
    {
        /// <summary>
        /// Processes HTTP requests and routes them to appropriate authentication handlers based on request path and method.
        /// This middleware acts as a dispatcher for different authentication mechanisms:
        /// - Local authentication (username/password with optional TOTP)
        /// - Google OAuth 2.0 with PKCE (Proof Key for Code Exchange)
        /// - Facebook OAuth 2.0 with state validation
        /// </summary>
        /// <param name="context">The HTTP context for the current request</param>
        /// <param name="localAuth">Service for handling local username/password authentication</param>
        /// <param name="googleOAuth">Service for handling Google OAuth authentication with PKCE</param>
        /// <param name="facebookOAuth">Service for handling Facebook OAuth authentication</param>
        /// <returns>A task that represents the asynchronous operation</returns>
        public async Task InvokeAsync(HttpContext context,
            ILocalAuth localAuth,
            IGoogleOAuth googleOAuth,
            IMicrosoftOAuth microsoftOAuth,
            IGitHubOAuth gitHubOAuth,
            IFacebookOAuth facebookOAuth
            )
        {
            // Handle Google OAuth login initiation
            if (googleOAuth.IsLogin(context))
            {
                await googleOAuth.HandleLoginAsync(context);
                return;
            }

            // Handle Google OAuth callback after user authorization
            if (googleOAuth.IsCallback(context))
            {
                await googleOAuth.HandleLoginCallback(context);
                return;
            }

            // Handle Microsof OAuth login initiation
            if (microsoftOAuth.IsLogin(context))
            {
                await microsoftOAuth.HandleLoginAsync(context);
                return;
            }

            // Handle Microsof OAuth callback after user authorization
            if (microsoftOAuth.IsCallback(context))
            {
                await microsoftOAuth.HandleLoginCallback(context);
                return;
            }

            // Handle GitHub OAuth login initiation
            if (gitHubOAuth.IsLogin(context))
            {
                await gitHubOAuth.HandleLoginAsync(context);
                return;
            }

            // Handle GitHub OAuth callback after user authorization
            if (gitHubOAuth.IsCallback(context))
            {
                await gitHubOAuth.HandleLoginCallback(context);
                return;
            }

            // Handle Facebook OAuth login initiation
            if (facebookOAuth.IsLogin(context))
            {
                await facebookOAuth.HandleLoginAsync(context);
                return;
            }

            // Handle Facebook OAuth callback after user authorization
            if (facebookOAuth.IsCallback(context))
            {
                await facebookOAuth.HandleLoginCallback(context);
                return;
            }

            // Handle local username/password login requests (POST /login)
            if (localAuth.IsLogin(context))
            {
                await localAuth.HandleLoginAsync(context);
                return;
            }

            // Handle user logout requests (POST /logout)
            if (localAuth.IsLogout(context))
            {
                await localAuth.HandleLogoutAsync(context);
                return;
            }

            // Continue to next middleware for all other requests
            await next(context);
        }
    }
}