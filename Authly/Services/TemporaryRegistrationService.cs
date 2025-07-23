using Authly.Configuration;
using Microsoft.Extensions.Options;

namespace Authly.Services
{
    /// <summary>
    /// Interface for managing temporary registration settings
    /// </summary>
    public interface ITemporaryRegistrationService
    {
        /// <summary>
        /// Gets whether temporary registration is currently enabled
        /// </summary>
        bool IsTemporaryRegistrationEnabled { get; }

        /// <summary>
        /// Gets the remaining time for temporary registration
        /// </summary>
        TimeSpan? RemainingTime { get; }

        /// <summary>
        /// Gets the end time of temporary registration
        /// </summary>
        DateTime? EndTime { get; }

        /// <summary>
        /// Enables temporary registration for the specified duration
        /// </summary>
        /// <param name="durationMinutes">Duration in minutes</param>
        Task EnableTemporaryRegistrationAsync(int durationMinutes);

        /// <summary>
        /// Disables temporary registration
        /// </summary>
        Task DisableTemporaryRegistrationAsync();

        /// <summary>
        /// Gets whether registration is allowed (either configured or temporary)
        /// </summary>
        bool IsRegistrationAllowed { get; }

        /// <summary>
        /// Event triggered when temporary registration status changes
        /// </summary>
        event Action? TemporaryRegistrationChanged;
    }

    /// <summary>
    /// Service for managing temporary registration settings
    /// </summary>
    public class TemporaryRegistrationService : ITemporaryRegistrationService
    {
        private readonly ApplicationOptions _options;
        private readonly IApplicationLogger _logger;
        private DateTime? _temporaryRegistrationEnd;
        private readonly object _lock = new object();

        public TemporaryRegistrationService(IOptions<ApplicationOptions> options, IApplicationLogger logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        public bool IsTemporaryRegistrationEnabled
        {
            get
            {
                lock (_lock)
                {
                    return _temporaryRegistrationEnd.HasValue && _temporaryRegistrationEnd > DateTime.UtcNow;
                }
            }
        }

        public TimeSpan? RemainingTime
        {
            get
            {
                lock (_lock)
                {
                    if (!IsTemporaryRegistrationEnabled)
                        return null;
                    
                    return _temporaryRegistrationEnd!.Value - DateTime.UtcNow;
                }
            }
        }

        public DateTime? EndTime
        {
            get
            {
                lock (_lock)
                {
                    return _temporaryRegistrationEnd;
                }
            }
        }

        public bool IsRegistrationAllowed => _options.AllowRegistration || IsTemporaryRegistrationEnabled;

        public event Action? TemporaryRegistrationChanged;

        public async Task EnableTemporaryRegistrationAsync(int durationMinutes)
        {
            if (durationMinutes <= 0)
                throw new ArgumentException("Duration must be positive", nameof(durationMinutes));

            lock (_lock)
            {
                _temporaryRegistrationEnd = DateTime.UtcNow.AddMinutes(durationMinutes);
            }

            _logger.Log("TemporaryRegistration", $"Enabled temporary registration for {durationMinutes} minutes until {_temporaryRegistrationEnd}");
            
            TemporaryRegistrationChanged?.Invoke();
            
            // Schedule automatic disable
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromMinutes(durationMinutes));
                await DisableTemporaryRegistrationAsync();
            });
        }

        public async Task DisableTemporaryRegistrationAsync()
        {
            bool wasEnabled;
            lock (_lock)
            {
                wasEnabled = IsTemporaryRegistrationEnabled;
                _temporaryRegistrationEnd = null;
            }

            if (wasEnabled)
            {
                _logger.Log("TemporaryRegistration", "Disabled temporary registration");
                TemporaryRegistrationChanged?.Invoke();
            }

            await Task.CompletedTask;
        }
    }
}