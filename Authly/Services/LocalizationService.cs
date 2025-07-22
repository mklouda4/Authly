using Microsoft.Extensions.Localization;
using System.Globalization;
using Microsoft.AspNetCore.Localization;

namespace Authly.Services
{
    /// <summary>
    /// Interface for localization services
    /// </summary>
    public interface ILocalizationService
    {
        /// <summary>
        /// Gets localized string by key
        /// </summary>
        /// <param name="key">Localization key</param>
        /// <returns>Localized string</returns>
        string GetString(string key);
        
        /// <summary>
        /// Gets localized string by key with parameters
        /// </summary>
        /// <param name="key">Localization key</param>
        /// <param name="args">Parameters for string formatting</param>
        /// <returns>Localized string</returns>
        string GetString(string key, params object[] args);
        
        /// <summary>
        /// Gets current culture
        /// </summary>
        /// <returns>Current culture info</returns>
        CultureInfo GetCurrentCulture();
        
        /// <summary>
        /// Sets current culture
        /// </summary>
        /// <param name="culture">Culture to set</param>
        void SetCurrentCulture(string culture);
        
        /// <summary>
        /// Gets available cultures
        /// </summary>
        /// <returns>List of available cultures</returns>
        IEnumerable<Culture> GetAvailableCultures();
    }

    /// <summary>
    /// Implementation of localization service
    /// </summary>
    public class LocalizationService(
        IStringLocalizer<LocalizationService> localizer,
        ILogger<LocalizationService> logger,
        IHttpContextAccessor httpContextAccessor) : ILocalizationService
    {

        /// <summary>
        /// Gets localized string by key
        /// </summary>
        public string GetString(string key)
        {
            try
            {
                var localizedString = localizer[key];
                
                // If the string is not found (ResourceNotFound), return the key as fallback
                if (localizedString.ResourceNotFound)
                {
                    logger.LogWarning("Localized string not found for key: {Key}", key);
                    return key;
                }
                
                return localizedString.Value;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error getting localized string for key: {Key}", key);
                return key; // Return key as fallback
            }
        }

        /// <summary>
        /// Gets localized string by key with parameters
        /// </summary>
        public string GetString(string key, params object[] args)
        {
            try
            {
                var localizedString = localizer[key, args];
                
                if (localizedString.ResourceNotFound)
                {
                    logger.LogWarning("Localized string not found for key: {Key}", key);
                    return key;
                }
                
                return localizedString.Value;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error getting localized string for key: {Key}", key);
                return key; // Return key as fallback
            }
        }

        /// <summary>
        /// Gets current culture
        /// </summary>
        public CultureInfo GetCurrentCulture()
            => CultureInfo.CurrentCulture;

        /// <summary>
        /// Sets current culture
        /// </summary>
        public void SetCurrentCulture(string culture)
        {
            try
            {
                var cultureInfo = new CultureInfo(culture);
                
                // Set thread culture
                Thread.CurrentThread.CurrentCulture = cultureInfo;
                Thread.CurrentThread.CurrentUICulture = cultureInfo;
                
                // Set culture for current context
                CultureInfo.CurrentCulture = cultureInfo;
                CultureInfo.CurrentUICulture = cultureInfo;
                
                // Set culture cookie for persistence across requests
                var httpContext = httpContextAccessor.HttpContext;
                if (httpContext != null)
                {
                    try
                    {
                        var requestCulture = new RequestCulture(cultureInfo);
                        var cookieValue = CookieRequestCultureProvider.MakeCookieValue(requestCulture);
                        
                        httpContext.Response.Cookies.Append(
                            CookieRequestCultureProvider.DefaultCookieName,
                            cookieValue,
                            new CookieOptions
                            {
                                Expires = DateTimeOffset.UtcNow.AddYears(1),
                                HttpOnly = false,
                                Secure = httpContext.Request.IsHttps,
                                SameSite = SameSiteMode.Lax,
                                Path = "/"
                            });
                        
                        logger.LogInformation("Culture cookie set to: {Culture}", culture);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Error setting culture cookie");
                    }
                }
                
                logger.LogInformation("Culture set to: {Culture}", culture);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error setting culture: {Culture}", culture);
            }
        }

        /// <summary>
        /// Gets available cultures
        /// </summary>
        public IEnumerable<Culture> GetAvailableCultures()
        {
            return
            [
                new Culture("en-US"),
                new Culture("cs-CZ"),
                new Culture("de-DE"),
                new Culture("fr-FR")
            ];
        }
    }

    public class Culture(string kod)
    {
        public string Code => kod;
        public string DisplayName => Code[..2].ToUpper();
        public CultureInfo CultureInfo => new(Code);
    }
}