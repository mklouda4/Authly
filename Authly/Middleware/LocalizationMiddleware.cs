using Authly.Authorization.UserStorage;
using Authly.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Localization;
using System.Globalization;

namespace Authly.Middleware
{
    /// <summary>
    /// Middleware pro nastavení kultury z localStorage
    /// </summary>
    public class LocalizationMiddleware(RequestDelegate next, IApplicationLogger logger, LocalizationService localizationService)
    {
        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                // Handle login requests
                if (context.Request.Path == "/culture")
                {
                    SetCulture(context, null);
                    return;
                }

                // Skip Blazor SignalR requests
                if (context.Request.Path.StartsWithSegments("/_blazor"))
                {
                    await next(context);
                    return;
                }

                // Check if response has already started
                if (context.Response.HasStarted)
                {
                    await next(context);
                    return;
                }

                // Continue to next middleware for all other requests
                await next(context);
            }
            catch (Exception ex)
            {
                logger.LogError("LocalizationMiddleware", "Error in LocalizationMiddleware", ex);
            }
        }

        private void SetCulture(HttpContext context, string? culture)
        {
            try
            {
                var supportedCultures = localizationService.GetAvailableCultures().Select(x => x.Code).ToArray();
                
                if (culture != null && supportedCultures.Contains(culture))
                {
                    var cultureInfo = new CultureInfo(culture);
                    CultureInfo.CurrentCulture =
                    CultureInfo.CurrentUICulture =
                    CultureInfo.DefaultThreadCurrentCulture =
                    CultureInfo.DefaultThreadCurrentUICulture = cultureInfo;


                    // Nastav culture cookie pouze pokud response ještě nezačal
                    if (!context.Response.HasStarted)
                    {
                        var requestCulture = new RequestCulture(cultureInfo);
                        var cookieValue = CookieRequestCultureProvider.MakeCookieValue(requestCulture);
                        
                        context.Response.Cookies.Append(
                            CookieRequestCultureProvider.DefaultCookieName,
                            cookieValue,
                            new CookieOptions
                            {
                                Expires = DateTimeOffset.UtcNow.AddYears(1),
                                HttpOnly = false,
                                Secure = context.Request.IsHttps,
                                SameSite = SameSiteMode.Lax,
                                Path = "/"
                            });
                    }
                    
                    logger.Log("LocalizationMiddleware", $"Culture set to: {culture}");
                }
            }
            catch (Exception ex)
            {
                logger.LogError("LocalizationMiddleware", $"Error setting culture: {culture}", ex);
            }
        }
    }
}