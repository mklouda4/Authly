namespace Authly.Services
{
    /// <summary>
    /// Custom logger provider for Entity Framework that uses IApplicationLogger
    /// </summary>
    public class EntityFrameworkApplicationLoggerProvider : ILoggerProvider
    {
        private readonly IApplicationLogger _applicationLogger;

        public EntityFrameworkApplicationLoggerProvider(IApplicationLogger applicationLogger)
        {
            _applicationLogger = applicationLogger;
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new EntityFrameworkApplicationLogger(_applicationLogger, categoryName);
        }

        public void Dispose()
        {
            // Nothing to dispose
        }
    }
}