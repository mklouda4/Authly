using Authly.Authorization;
using Authly.Authorization.Facebook;
using Authly.Authorization.GitHub;
using Authly.Authorization.Google;
using Authly.Authorization.Local;
using Authly.Authorization.Microsoft;
using Authly.Authorization.UserStorage;
using Authly.Components;
using Authly.Configuration;
using Authly.Models;
using Authly.Services;
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.Options;
using Prometheus;

namespace Authly
{
    /// <summary>
    /// Main application entry point and configuration class
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Main entry point for the Authly application
        /// </summary>
        /// <param name="args">Command line arguments</param>
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Configure environment-based overrides for Docker
            ConfigureEnvironmentOverrides(builder.Configuration);

            // Application configuration
            _ = builder.Services.Configure<ApplicationOptions>(
                builder.Configuration.GetSection(ApplicationOptions.SectionName));
            // Security configuration
            _ = builder.Services.Configure<UserLockoutOptions>(
                builder.Configuration.GetSection("Security:UserLockout"));
            _ = builder.Services.Configure<IpRateLimitingOptions>(
                builder.Configuration.GetSection("Security:IpRateLimit"));

            // Get base application options
            var appOptionsBase = builder.Configuration.GetSection(ApplicationOptions.SectionName).Get<ApplicationOptions>() ?? new ApplicationOptions();

            // Configure localization
            _ = builder.Services.AddLocalization(options =>
            {
                options.ResourcesPath = "Resources";
            });

            _ = builder.Services.Configure<RequestLocalizationOptions>(options =>
            {
                var serviceProvider = builder.Services.BuildServiceProvider();
                var localizationService = serviceProvider.GetRequiredService<ILocalizationService>();

                var supportedCultures = localizationService
                    .GetAvailableCultures()
                    .Select(c => c.CultureInfo)
                    .ToArray();

                options.DefaultRequestCulture = new RequestCulture(supportedCultures.First().Name);
                options.SupportedCultures = supportedCultures;
                options.SupportedUICultures = supportedCultures;

                // Use standard localization providers
                options.RequestCultureProviders.Clear();
                options.RequestCultureProviders.Add(new QueryStringRequestCultureProvider());
                options.RequestCultureProviders.Add(new CookieRequestCultureProvider());
                options.RequestCultureProviders.Add(new AcceptLanguageHeaderRequestCultureProvider());
            });

            // Add services to the container.
            _ = builder.Services.AddRazorComponents()
                .AddInteractiveServerComponents();

            // HttpContextAccessor for accessing HttpContext in services
            _ = builder.Services.AddHttpContextAccessor();

            // Add session support for temporary credential storage during TOTP validation
            _ = builder.Services.AddDistributedMemoryCache();
            _ = builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(5); // Session timeout for security
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            });

            var keyDir = new DirectoryInfo(Environment.GetEnvironmentVariable("AUTHLY_KEY_DIRECTORY") ?? "/app/keys");
            if (builder.Environment.IsDevelopment())
                keyDir = new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), "keys"));

            // Configure data protection for OAuth state validation
            _ = builder.Services.AddDataProtection()
                .PersistKeysToFileSystem(keyDir)
                .SetApplicationName(appOptionsBase.Name);

            // Application services registration
            _ = builder.Services.AddScoped<IApplicationService, ApplicationService>();
            _ = builder.Services.AddSingleton<IApplicationLogger, ApplicationLogger>();
            _ = builder.Services.AddScoped<ILocalizationService, LocalizationService>();

            // Register security service
            _ = builder.Services.AddSingleton<ISecurityService, SecurityService>();

            // Register metrics service
            _ = builder.Services.AddSingleton<IMetricsService, MetricsService>();

            // Register session tracking service
            _ = builder.Services.AddSingleton<ISessionTrackingService, SessionTrackingService>();

            // Register health checks
            _ = builder.Services.AddHealthChecks()
                .AddCheck<AuthlyHealthCheck>($"{appOptionsBase.Name}_health".ToLower())
                .AddCheck<ReadinessHealthCheck>("readiness")
                .AddCheck<LivenessHealthCheck>("liveness");

            // Register HttpClient with configuration for local API calls
            _ = builder.Services.AddHttpClient("LocalApi", client =>
            {
                // Configuration based on environment - in development we use localhost
                if (builder.Environment.IsDevelopment())
                {
                    client.BaseAddress = new Uri("https://localhost:7283/");
                }
                client.Timeout = TimeSpan.FromSeconds(30);
            });

            // Register standard HttpClient for external calls
            _ = builder.Services.AddHttpClient();

            // Register HttpClient for AuthService - prefers dynamic configuration
            _ = builder.Services.AddScoped<HttpClient>(sp =>
            {
                var httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
                var httpContextAccessor = sp.GetRequiredService<IHttpContextAccessor>();

                // Attempt dynamic BaseAddress configuration from HttpContext
                var httpContext = httpContextAccessor.HttpContext;
                if (httpContext != null)
                {
                    try
                    {
                        var client = httpClientFactory.CreateClient();
                        var request = httpContext.Request;
                        var baseAddress = $"{request.Scheme}://{request.Host}";
                        client.BaseAddress = new Uri(baseAddress);
                        client.Timeout = TimeSpan.FromSeconds(30);
                        return client;
                    }
                    catch
                    {
                        // Fallback to LocalApi if dynamic configuration fails
                    }
                }

                // Fallback to LocalApi client
                return httpClientFactory.CreateClient("LocalApi");
            });

            // User Storage services
            _ = builder.Services.AddScoped<InMemoryUserStorage>(sp =>
                new InMemoryUserStorage(
                    sp.GetRequiredService<IWebHostEnvironment>(),
                    sp.GetRequiredService<IApplicationLogger>(),
                    sp.GetRequiredService<IApplicationService>()
                ));
            _ = builder.Services.AddScoped<IUserStorageFactory, UserStorageFactory>();
            _ = builder.Services.AddScoped<IUserStorage>(sp => sp.GetRequiredService<IUserStorageFactory>().GetUserStorage());

            // Register IContextProvider
            _ = builder.Services.AddScoped<IContextProvider, HttpContextProvider>();

            // Register IUrlValidator
            _ = builder.Services.AddSingleton<IUrlValidator, UrlValidator>();

            // ASP.NET Core Identity with custom implementations
            _ = builder.Services.AddIdentity<User, IdentityRole>(options =>
            {
                // Password settings
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 1;
                options.Password.RequiredUniqueChars = 1;

                // User settings
                options.User.RequireUniqueEmail = false;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

                // Sign in settings
                options.SignIn.RequireConfirmedEmail = false;
                options.SignIn.RequireConfirmedPhoneNumber = false;
            })
            .AddUserStore<CustomUserStore>()
            .AddRoleStore<CustomRoleStore>()
            .AddUserManager<CustomUserManager>()
            .AddSignInManager<CustomSignInManager>()
            .AddDefaultTokenProviders();

            // Configure Authentication with External Providers (conditionally)
            _ = builder.Services.AddAuthentication();
            _ = builder.Services
                .AddLocalAuth()
                .AddGoogleOAuth()
                .AddMicrosoftOAuth()
                .AddGitHubOAuth()
                .AddFacebookOAuth();

            // Cookie Authentication (will be used instead of Identity.Application)
            _ = builder.Services.ConfigureApplicationCookie(options =>
            {
                var serviceProvider = builder.Services.BuildServiceProvider();
                var applicationService = serviceProvider.GetRequiredService<IApplicationService>();

                options.Cookie.Name = $"{applicationService.ApplicationName}Auth";
                if(!string.IsNullOrEmpty(applicationService.DomainName))
                    options.Cookie.Domain = $".{applicationService.DomainName}";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromDays(30); // 30 days validity
                options.SlidingExpiration = true; // Renewal on activity
                options.LoginPath = LocalAuth.LoginUri;
                options.LogoutPath = LocalAuth.LogoutUri;
                options.AccessDeniedPath = LocalAuth.LoginUri;
                options.ReturnUrlParameter = "returnUrl";
            });

            _ = builder.Services.AddAuthorization();

            // Authentication State Provider for Blazor Server
            _ = builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

            // Register ThemeService for server
            _ = builder.Services.AddScoped<IThemeService, ThemeService>();

            // Register AuthService for authentication
            _ = builder.Services.AddScoped<IAuthService, AuthService>();

            // Register QR Code service
            _ = builder.Services.AddScoped<IQRCodeService, QRCodeService>();

            // Register TOTP service
            _ = builder.Services.AddScoped<ITotpService, TotpService>();

            var app = builder.Build();

            // Configure Prometheus metrics if enabled
            var appOptions = app.Services.GetRequiredService<IOptions<ApplicationOptions>>();
            if (appOptions.Value.EnableMetrics)
            {
                // Add Prometheus metrics endpoint
                _ = app.UseMetricServer("/metrics");

                // Add HTTP request metrics
                _ = app.UseHttpMetrics();
            }

            // Configure health check endpoints
            _ = app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
            {
                ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
            });

            _ = app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
            {
                Predicate = check => check.Tags.Contains("readiness") || check.Name == "readiness",
                ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
            });

            _ = app.MapHealthChecks("/health/live", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
            {
                Predicate = check => check.Tags.Contains("liveness") || check.Name == "liveness",
                ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
            });

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                // Remove WebAssembly debugging
            }
            else
            {
                _ = app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                _ = app.UseHsts();
            }

            _ = app.UseHttpsRedirection();
            _ = app.UseStaticFiles();
            _ = app.UseRouting();

            // Use standard request localization middleware
            _ = app.UseRequestLocalization();

            // Add session middleware before authentication
            _ = app.UseSession();

            // Authentication & Authorization middleware
            _ = app.UseAuthentication();
            _ = app.UseAuthorization();

            // AuthMiddleware AFTER authentication but BEFORE Blazor components
            _ = app.UseMiddleware<Authly.Middleware.AuthMiddleware>();

            // ExternalAuthMiddleware for reverse proxy SSO support
            _ = app.UseMiddleware<Authly.Middleware.ExternalAuthMiddleware>();

            _ = app.UseAntiforgery();

            _ = app.MapRazorComponents<App>()
                .AddInteractiveServerRenderMode();

            app.Run();
        }

        /// <summary>
        /// Configures environment variable overrides for Docker deployment
        /// </summary>
        /// <param name="configuration">Configuration builder</param>
        private static void ConfigureEnvironmentOverrides(IConfiguration configuration)
        {
            // Map clean environment variables to configuration paths
            var environmentMappings = new Dictionary<string, string>
            {
                // Application settings
                ["AUTHLY_NAME"] = "Application:Name",
                ["AUTHLY_DOMAIN"] = "Application:Domain",
                ["AUTHLY_BASE_URL"] = "Application:BaseUrl",
                ["AUTHLY_VERSION"] = "Application:Version",
                ["AUTHLY_DEBUG_LOGGING"] = "Application:DebugLogging",
                ["AUTHLY_ENABLE_METRICS"] = "Application:EnableMetrics",
                ["AUTHLY_ALLOW_REGISTRATION"] = "Application:AllowRegistration",

                // External authentication settings
                ["AUTHLY_ENABLE_GOOGLE"] = "Application:ExternalAuth:EnableGoogle",
                ["AUTHLY_ENABLE_MICROSOFT"] = "Application:ExternalAuth:EnableMicrosoft",
                ["AUTHLY_ENABLE_GITHUB"] = "Application:ExternalAuth:EnableGitHub",
                ["AUTHLY_ENABLE_FACEBOOK"] = "Application:ExternalAuth:EnableFacebook",

                // User lockout settings
                ["AUTHLY_USER_LOCKOUT_ENABLED"] = "Security:UserLockout:Enabled",
                ["AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS"] = "Security:UserLockout:MaxFailedAttempts",
                ["AUTHLY_USER_LOCKOUT_DURATION"] = "Security:UserLockout:LockoutDurationMinutes",
                ["AUTHLY_USER_LOCKOUT_SLIDING_WINDOW"] = "Security:UserLockout:SlidingWindow",
                ["AUTHLY_USER_LOCKOUT_WINDOW"] = "Security:UserLockout:WindowMinutes",

                // IP rate limiting settings
                ["AUTHLY_IP_RATE_LIMIT_ENABLED"] = "Security:IpRateLimit:Enabled",
                ["AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS"] = "Security:IpRateLimit:MaxAttemptsPerIp",
                ["AUTHLY_IP_RATE_LIMIT_BAN_DURATION"] = "Security:IpRateLimit:BanDurationMinutes",
                ["AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW"] = "Security:IpRateLimit:SlidingWindow",
                ["AUTHLY_IP_RATE_LIMIT_WINDOW"] = "Security:IpRateLimit:WindowMinutes",

                // OAuth settings - Google
                ["GOOGLE_CLIENT_ID"] = "Authentication:Google:ClientId",
                ["GOOGLE_CLIENT_SECRET"] = "Authentication:Google:ClientSecret",
                // OAuth settings - Facebook
                ["FACEBOOK_APP_ID"] = "Authentication:Facebook:AppId",
                ["FACEBOOK_APP_SECRET"] = "Authentication:Facebook:AppSecret",
                // OAuth settings - Microsoft
                ["MICROSOFT_CLIENT_ID"] = "Authentication:Microsoft:ClientId",
                ["MICROSOFT_CLIENT_SECRET"] = "Authentication:Microsoft:ClientSecret",
                ["MICROSOFT_TENANT_ID"] = "Authentication:Microsoft:TenantId",
                // OAuth settings - GitHub
                ["GITHUB_CLIENT_ID"] = "Authentication:GitHub:ClientId",
                ["GITHUB_CLIENT_SECRET"] = "Authentication:GitHub:ClientSecret",
            };

            // Apply environment variable overrides
            foreach (var mapping in environmentMappings)
            {
                var envValue = Environment.GetEnvironmentVariable(mapping.Key);
                if (!string.IsNullOrEmpty(envValue))
                {
                    configuration[mapping.Value] = envValue;
                }
            }
        }
    }
}