using Authly.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Authly.Services
{
    /// <summary>
    /// Interface for application logging service
    /// </summary>
    public interface IApplicationLogger
    {
        /// <summary>
        /// Log a general message
        /// </summary>
        void Log(string category, string message);
        
        /// <summary>
        /// Log an debug message
        /// </summary>
        void LogDebug(string category, string message, Exception? exception = null);

        /// <summary>
        /// Log an error message with optional exception
        /// </summary>
        void LogError(string category, string message, Exception? exception = null);
        
        /// <summary>
        /// Log an informational message
        /// </summary>
        void LogInfo(string category, string message);
        
        /// <summary>
        /// Log a warning message
        /// </summary>
        void LogWarning(string category, string message, Exception? exception = null);
        
        /// <summary>
        /// Indicates if logging is enabled
        /// </summary>
        bool IsEnabled { get; }

        /// <summary>
        /// Event triggered when a new log entry is added
        /// </summary>
        event Action<LogEntry>? LogAdded;
        /// <summary>
        /// Return stored logs
        /// </summary>
        /// <returns></returns>
        IEnumerable<LogEntry> GetLogs();

        /// <summary>
        /// Clear stored logs
        /// </summary>
        /// <returns></returns>
        void ClearLogs();
    }

    /// <summary>
    /// Application logger that respects debug configuration
    /// </summary>
    public class ApplicationLogger(IOptions<ApplicationOptions> options, ILogger<ApplicationLogger> logger) : IApplicationLogger
    {
        private readonly ApplicationOptions _options = options.Value;
        private readonly ConcurrentQueue<LogEntry> _logs = new();
        private const int MaxLogEntries = 50;

        /// <summary>
        /// Indicates if debug logging is enabled in configuration
        /// </summary>
        public bool IsEnabled => _options.DebugLogging;

        /// <summary>
        /// Log a general debug message
        /// </summary>
        public void Log(string category, string message)
        {
            if (IsEnabled)
            {
                var logMessage = $"[{category}] {message}";
                Console.WriteLine(logMessage);
                logger.LogDebug(logMessage);
            }
            AddLogEntry(category, "DEBUG", message);
        }

        /// <summary>
        /// Log an debug message
        /// </summary>
        public void LogDebug(string category, string message, Exception? exception = null)
        {
            if (IsEnabled)
            {
                var logMessage = $"[{category}] DEBUG: {message}";
                Debug.WriteLine(logMessage);
                logger.LogDebug(logMessage);
            }
            AddLogEntry(category, "DEBUG", message, exception);
        }

        /// <summary>
        /// Log an error message with optional exception details
        /// </summary>
        public void LogError(string category, string message, Exception? exception = null)
        {
            if (IsEnabled)
            {
                var logMessage = $"[{category}] ERROR: {message}";
                Console.WriteLine(logMessage);

                if (exception != null)
                {
                    Console.WriteLine($"[{category}] Exception: {exception.Message}");
                    Console.WriteLine($"[{category}] StackTrace: {exception.StackTrace}");
                    logger.LogError(exception, logMessage);
                }
                else
                {
                    logger.LogError(logMessage);
                }
            }
            AddLogEntry(category, "ERROR", message, exception);
        }

        /// <summary>
        /// Log an informational message
        /// </summary>
        public void LogInfo(string category, string message)
        {
            if (IsEnabled)
            {
                var logMessage = $"[{category}] INFO: {message}";
                Console.WriteLine(logMessage);
                logger.LogInformation(logMessage);
            }
            AddLogEntry(category, "INFO", message);
        }

        /// <summary>
        /// Log a warning message
        /// </summary>
        public void LogWarning(string category, string message, Exception? exception = null)
        {
            if (IsEnabled)
            {
                var logMessage = $"[{category}] WARNING: {message}";
                Console.WriteLine(logMessage);
                logger.LogWarning(logMessage);
            }
            AddLogEntry(category, "WARNING", message, exception);
        }

        /// <summary>
        /// Event triggered when a new log entry is added
        /// </summary>
        public event Action<LogEntry>? LogAdded;

        /// <summary>
        /// Adds a log entry to the internal queue and triggers the LogAdded event.
        /// </summary>
        /// <param name="category"></param>
        /// <param name="level"></param>
        /// <param name="message"></param>
        /// <param name="exception"></param>
        private void AddLogEntry(string category, string level, string message, Exception? exception = null)
        {
            var entry = new LogEntry
            {
                Timestamp = DateTime.Now,
                Category = category,
                Level = level,
                Message = message,
                Exception = exception
            };

            _logs.Enqueue(entry);

            while (_logs.Count > MaxLogEntries)
            {
                _logs.TryDequeue(out _);
            }

            LogAdded?.Invoke(entry);
        }

        /// <summary>
        /// Returns stored logs in reverse order (most recent first).
        /// </summary>
        /// <returns></returns>
        public IEnumerable<LogEntry> GetLogs()
            => _logs.ToArray().Reverse();

        /// <summary>
        /// Clears all stored logs from the logger.
        /// </summary>
        public void ClearLogs()
        {
            while (_logs.TryDequeue(out _));
        }
    }

    /// <summary>
    /// Represents a single log entry in the application logger.
    /// </summary>
    public class LogEntry
    {
        /// <summary>
        /// Timestamp of when the log entry was created.
        /// </summary>
        public DateTime Timestamp { get; set; }
        /// <summary>
        /// Category of the log entry (e.g., "Auth", "Database").
        /// </summary>
        public string Category { get; set; } = string.Empty;
        /// <summary>
        /// Log level of the entry (e.g., "DEBUG", "INFO", "WARNING", "ERROR").
        /// </summary>
        public string Level { get; set; } = "INFO";
        /// <summary>
        /// Message content of the log entry.
        /// </summary>
        public string Message { get; set; } = string.Empty;
        /// <summary>
        /// Optional exception associated with the log entry, if any.
        /// </summary>
        public Exception? Exception { get; set; }
    }
}