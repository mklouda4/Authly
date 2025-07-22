namespace Authly.Authorization.UserStorage
{
    /// <summary>
    /// Interface for providing context information about the current request/user
    /// </summary>
    public interface IContextProvider
    {
        /// <summary>
        /// Gets the current context identifier (usually username or "anonymous")
        /// </summary>
        /// <returns>Context identifier string</returns>
        string GetCurrentContext();
    }

    /// <summary>
    /// HTTP context-based implementation of IContextProvider
    /// </summary>
    public class HttpContextProvider : IContextProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        /// <summary>
        /// Initializes a new instance of HttpContextProvider
        /// </summary>
        /// <param name="httpContextAccessor">HTTP context accessor service</param>
        public HttpContextProvider(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Gets the current user context from HTTP request
        /// </summary>
        /// <returns>Username if authenticated, otherwise "anonymous"</returns>
        public string GetCurrentContext()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User?.Identity?.IsAuthenticated == true)
            {
                return httpContext.User.Identity.Name ?? "anonymous";
            }
            return "anonymous";
        }
    }
}