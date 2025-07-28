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
        void LogDebug(string category, string message);

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
        void LogWarning(string category, string message);
        
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
    public class ApplicationLogger : IApplicationLogger
    {
        private readonly ApplicationOptions _options;
        private readonly ILogger<ApplicationLogger> _logger;

        public ApplicationLogger(IOptions<ApplicationOptions> options, ILogger<ApplicationLogger> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// Indicates if debug logging is enabled in configuration
        /// </summary>
        public bool IsEnabled => _options.DebugLogging;

        /// <summary>
        /// Log a general debug message
        /// </summary>
        public void Log(string category, string message)
        {
            if (!IsEnabled) return;
            
            var logMessage = $"[{category}] {message}";
            Console.WriteLine(logMessage);
            _logger.LogDebug(logMessage);

            AddLogEntry(category, "DEBUG", message);
        }

        /// <summary>
        /// Log an debug message
        /// </summary>
        public void LogDebug(string category, string message)
        {
            if (!IsEnabled) return;

            var logMessage = $"[{category}] DEBUG: {message}";
            Debug.WriteLine(logMessage);
            _logger.LogDebug(logMessage);

            AddLogEntry(category, "DEBUG", message);
        }

        /// <summary>
        /// Log an error message with optional exception details
        /// </summary>
        public void LogError(string category, string message, Exception? exception = null)
        {
            if (!IsEnabled) return;
            
            var logMessage = $"[{category}] ERROR: {message}";
            Console.WriteLine(logMessage);
            
            if (exception != null)
            {
                Console.WriteLine($"[{category}] Exception: {exception.Message}");
                Console.WriteLine($"[{category}] StackTrace: {exception.StackTrace}");
                _logger.LogError(exception, logMessage);
            }
            else
            {
                _logger.LogError(logMessage);
            }

            AddLogEntry(category, "ERROR", message, exception);
        }

        /// <summary>
        /// Log an informational message
        /// </summary>
        public void LogInfo(string category, string message)
        {
            if (!IsEnabled) return;
            
            var logMessage = $"[{category}] INFO: {message}";
            Console.WriteLine(logMessage);
            _logger.LogInformation(logMessage);

            AddLogEntry(category, "INFO", message);
        }

        /// <summary>
        /// Log a warning message
        /// </summary>
        public void LogWarning(string category, string message)
        {
            if (!IsEnabled) return;
            
            var logMessage = $"[{category}] WARNING: {message}";
            Console.WriteLine(logMessage);
            _logger.LogWarning(logMessage);

            AddLogEntry(category, "WARNING", message);
        }


        private readonly ConcurrentQueue<LogEntry> _logs = new();
        private const int MaxLogEntries = 50;

        public event Action<LogEntry>? LogAdded;

        private void AddLogEntry(string category, string level, string message, Exception? exception = null)
        {
            //if (!IsEnabled) return;

            var entry = new LogEntry
            {
                Timestamp = DateTime.Now,
                Category = category,
                Level = level,
                Message = message,
                Exception = exception
            };

            _logs.Enqueue(entry);

            // Odebereme nejstarší záznamy, pokud překročíme limit
            while (_logs.Count > MaxLogEntries)
            {
                _logs.TryDequeue(out _); // Bezpečně odeber nejstarší
            }

            LogAdded?.Invoke(entry);
        }

        public IEnumerable<LogEntry> GetLogs()
        {
            return _logs.ToArray().Reverse(); // Nejnovější první pro zobrazení
        }

        public void ClearLogs()
        {
            while (_logs.TryDequeue(out _)) { } // Vyprázdni queue
        }
    }

    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Level { get; set; } = "Information";
        public string Message { get; set; } = string.Empty;
        public Exception? Exception { get; set; }
    }
}