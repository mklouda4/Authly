using Microsoft.JSInterop;

namespace Authly.Services
{
    /// <summary>
    /// Interface for theme management service
    /// </summary>
    public interface IThemeService
    {
        /// <summary>
        /// Retrieves the current theme preference
        /// </summary>
        /// <returns>Current theme ("light" or "dark")</returns>
        Task<string> GetThemeAsync();
        
        /// <summary>
        /// Sets the user's theme preference
        /// </summary>
        /// <param name="theme">Theme to set ("light" or "dark")</param>
        Task SetThemeAsync(string theme);
    }

    /// <summary>
    /// Theme management service that persists user preferences in localStorage
    /// </summary>
    public class ThemeService(IJSRuntime jsRuntime, IApplicationLogger logger, IApplicationService applicationService) : IThemeService
    {

        /// <summary>
        /// Retrieves the current theme preference from localStorage or system preference
        /// </summary>
        public async Task<string> GetThemeAsync()
        {
            try
            {
                // 1. Try to load from localStorage
                var savedTheme = await jsRuntime.InvokeAsync<string>("localStorage.getItem", $"{applicationService.ApplicationName}-theme");
                if (!string.IsNullOrEmpty(savedTheme) && (savedTheme == "light" || savedTheme == "dark"))
                {
                    return savedTheme;
                }

                // 2. Fall back to system preference
                var systemPrefersDark = await jsRuntime.InvokeAsync<bool>("window.matchMedia('(prefers-color-scheme: dark)').matches");
                return systemPrefersDark ? "dark" : "light";
            }
            catch (Exception ex)
            {
                logger.LogError("ThemeService", "Error retrieving theme preference", ex);
                return "dark"; // Default to dark theme for better readability
            }
        }

        /// <summary>
        /// Saves the theme preference to localStorage with timestamp
        /// </summary>
        public async Task SetThemeAsync(string theme)
        {
            try
            {
                // Save theme to localStorage
                await jsRuntime.InvokeVoidAsync("localStorage.setItem", $"{applicationService.ApplicationName}-theme", theme);
                
                // Save timestamp for potential expiration tracking
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                await jsRuntime.InvokeVoidAsync("localStorage.setItem", $"{applicationService.ApplicationName}-theme-timestamp", timestamp.ToString());
                
                logger.Log("ThemeService", $"Theme preference set to: {theme}");
            }
            catch (Exception ex)
            {
                logger.LogError("ThemeService", "Error saving theme preference", ex);
            }
        }

        /// <summary>
        /// Checks if the stored theme preference has expired (optional utility method)
        /// </summary>
        /// <returns>True if expired or no timestamp found</returns>
        public async Task<bool> IsThemeExpiredAsync()
        {
            try
            {
                var timestampStr = await jsRuntime.InvokeAsync<string>("localStorage.getItem", $"{applicationService.ApplicationName}-theme-timestamp");
                if (string.IsNullOrEmpty(timestampStr) || !long.TryParse(timestampStr, out var timestamp))
                {
                    return true; // If no timestamp, consider expired
                }

                var savedTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
                var expiryTime = savedTime.AddDays(365); // 1 year expiry
                return DateTimeOffset.UtcNow > expiryTime;
            }
            catch (Exception ex)
            {
                logger.LogError("ThemeService", "Error checking theme expiration", ex);
                return true; // On error, consider expired
            }
        }
    }
}