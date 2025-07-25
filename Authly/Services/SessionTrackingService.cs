using Authly.Extension;
using System.Collections.Concurrent;

namespace Authly.Services
{
    /// <summary>
    /// Interface for tracking active user sessions
    /// </summary>
    public interface ISessionTrackingService
    {
        /// <summary>
        /// Records a new user session
        /// </summary>
        /// <param name="userName">The user name</param>
        void AddSession(string userName);

        /// <summary>
        /// Removes a user session
        /// </summary>
        /// <param name="userName">The user name</param>
        void RemoveSession(string userName);

        /// <summary>
        /// Gets the count of active user sessions
        /// </summary>
        /// <returns>Number of active sessions</returns>
        int GetActiveSessionCount();

        /// <summary>
        /// Gets the count of unique active users
        /// </summary>
        /// <returns>Number of unique active users</returns>
        int GetActiveUserCount();

        /// <summary>
        /// Cleans up expired sessions
        /// </summary>
        void CleanupExpiredSessions();
    }

    /// <summary>
    /// Session information for tracking
    /// </summary>
    public class SessionInfo
    {
        public string UserName { get; set; } = string.Empty;
        public string SessionId { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastActivity { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Service for tracking active user sessions and updating metrics
    /// </summary>
    public class SessionTrackingService : ISessionTrackingService
    {
        private readonly ConcurrentDictionary<string, SessionInfo> _activeSessions = new();
        private readonly IMetricsService _metricsService;
        private readonly IApplicationLogger _logger;
        private readonly Timer _cleanupTimer;
        private readonly TimeSpan _sessionTimeout = TimeSpan.FromMinutes(30); // Default session timeout

        public SessionTrackingService(IMetricsService metricsService, IApplicationLogger logger)
        {
            _metricsService = metricsService;
            _logger = logger;

            // Setup cleanup timer to run every 5 minutes
            _cleanupTimer = new Timer(
                _ => CleanupExpiredSessions(), 
                null, 
                TimeSpan.FromMinutes(5), 
                TimeSpan.FromMinutes(5));
        }

        /// <summary>
        /// Records a new user session and updates metrics
        /// </summary>
        public void AddSession(string userName)
        {
            var sessionId = userName.GetDeterministicStringFromString();
            try
            {

                var sessionInfo = new SessionInfo
                {
                    UserName = userName,
                    SessionId = sessionId,
                    CreatedAt = DateTime.UtcNow,
                    LastActivity = DateTime.UtcNow
                };

                _activeSessions.AddOrUpdate(sessionId, sessionInfo, (key, oldValue) => sessionInfo);
                
                var activeCount = GetActiveSessionCount();
                _metricsService.RecordActiveUserSessions(activeCount);
                
                _logger.Log("SessionTracking", $"Added session {sessionId} for user {userName}. Active sessions: {activeCount}");
            }
            catch (Exception ex)
            {
                _logger.LogError("SessionTracking", $"Error adding session {sessionId}", ex);
            }
        }

        /// <summary>
        /// Removes a user session and updates metrics
        /// </summary>
        public void RemoveSession(string userName)
        {
            var sessionId = userName.GetDeterministicStringFromString();
            try
            {
                if (_activeSessions.TryRemove(sessionId, out var removedSession))
                {
                    var activeCount = GetActiveSessionCount();
                    _metricsService.RecordActiveUserSessions(activeCount);
                    
                    _logger.Log("SessionTracking", $"Removed session {sessionId} for user {removedSession.UserName}. Active sessions: {activeCount}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("SessionTracking", $"Error removing session {sessionId}", ex);
            }
        }

        /// <summary>
        /// Gets the total count of active sessions
        /// </summary>
        public int GetActiveSessionCount()
        {
            return _activeSessions.Count;
        }

        /// <summary>
        /// Gets the count of unique active users
        /// </summary>
        public int GetActiveUserCount()
        {
            return _activeSessions.Values
                .Select(s => s.UserName)
                .Distinct()
                .Count();
        }

        /// <summary>
        /// Cleans up expired sessions based on timeout
        /// </summary>
        public void CleanupExpiredSessions()
        {
            return;
            try
            {
                var cutoffTime = DateTime.UtcNow.Subtract(_sessionTimeout);
                var expiredSessions = _activeSessions
                    .Where(kvp => kvp.Value.LastActivity < cutoffTime)
                    .Select(kvp => kvp.Value.UserName)
                    .ToList();

                foreach (var sessionId in expiredSessions)
                {
                    RemoveSession(sessionId);
                }

                if (expiredSessions.Any())
                {
                    _logger.Log("SessionTracking", $"Cleaned up {expiredSessions.Count} expired sessions");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("SessionTracking", "Error during session cleanup", ex);
            }
        }

        /// <summary>
        /// Updates the last activity time for a session
        /// </summary>
        public void UpdateSessionActivity(string sessionId)
        {
            if (_activeSessions.TryGetValue(sessionId, out var session))
            {
                session.LastActivity = DateTime.UtcNow;
            }
        }

        public void Dispose()
        {
            _cleanupTimer?.Dispose();
        }
    }
}