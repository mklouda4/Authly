using Authly.Services;

namespace Authly.Extension
{
    /// <summary>
    /// Extension methods for TimeSpan
    /// </summary>
    public static class TimeSpanExtensions
    {
        /// <summary>
        /// Converts a TimeSpan to a localized string representation.
        /// </summary>
        /// <param name="timeSpan"></param>
        /// <param name="localization"></param>
        /// <returns></returns>
        public static string ToLocalizedString(this TimeSpan timeSpan, ILocalizationService localization)
        {
            var localizedString = $"{timeSpan.Seconds}{localization.GetString("SecondsShort")}";

            if (timeSpan.TotalMinutes >= 1)
            {
                localizedString = $"{timeSpan.Minutes}{localization.GetString("MinutesShort")} {localizedString}";
            }
            if (timeSpan.TotalHours >= 1)
            {
                localizedString = $"{timeSpan.Hours}{localization.GetString("HoursShort")} {localizedString}";
            }
            if (timeSpan.TotalDays >= 1)
            {
                localizedString = $"{timeSpan.Days}{localization.GetString("DaysShort")} {localizedString}";
            }

            return localizedString.Trim();
        }
    }
}
