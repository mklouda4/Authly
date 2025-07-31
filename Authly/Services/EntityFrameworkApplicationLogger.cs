namespace Authly.Services
{
    /// <summary>
    /// Custom logger for Entity Framework that forwards to IApplicationLogger
    /// </summary>
    public class EntityFrameworkApplicationLogger : ILogger
    {
        private readonly IApplicationLogger _applicationLogger;
        private readonly string _categoryName;

        public EntityFrameworkApplicationLogger(IApplicationLogger applicationLogger, string categoryName)
        {
            _applicationLogger = applicationLogger;
            _categoryName = categoryName;
        }

        public IDisposable BeginScope<TState>(TState state)
        {
            return new NoOpDisposable();
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return _applicationLogger.IsEnabled;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;

            var message = formatter(state, exception);
            var category = "EntityFramework";

            switch (logLevel)
            {
                case LogLevel.Debug:
                case LogLevel.Trace:
#if DEBUG
                    _applicationLogger.LogDebug(category, $"[{_categoryName}] {message}");
#endif
                    break;
                case LogLevel.Information:
#if DEBUG
                    _applicationLogger.LogInfo(category, $"[{_categoryName}] {message}");
#endif
                    break;
                case LogLevel.Warning:
                    _applicationLogger.LogWarning(category, $"[{_categoryName}] {message}");
                    break;
                case LogLevel.Error:
                case LogLevel.Critical:
                    _applicationLogger.LogError(category, $"[{_categoryName}] {message}", exception);
                    break;
            }
        }

        private class NoOpDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }
}