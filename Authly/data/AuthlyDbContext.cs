using Microsoft.EntityFrameworkCore;
using Authly.Models;
using System.Text.Json;

namespace Authly.Data
{
    /// <summary>
    /// Database context for Authly application
    /// </summary>
    public class AuthlyDbContext : DbContext
    {
        public AuthlyDbContext(DbContextOptions<AuthlyDbContext> options) : base(options)
        {
        }

        // Database sets for the entities that replace JSON files
        public DbSet<OAuthClient> OAuthClients { get; set; }
        public DbSet<Token> Tokens { get; set; }
        public DbSet<IpLoginAttempt> IpLoginAttempts { get; set; }
        public DbSet<OAuthAuthorizationCode> OAuthAuthorizationCodes { get; set; }
        public DbSet<OAuthAccessToken> OAuthAccessTokens { get; set; }
        public DbSet<OAuthRefreshToken> OAuthRefreshTokens { get; set; }

        // Metrics entities
        public DbSet<LoginAttemptMetric> LoginAttemptMetrics { get; set; }
        public DbSet<SecurityEventMetric> SecurityEventMetrics { get; set; }
        public DbSet<ActiveSessionMetric> ActiveSessionMetrics { get; set; }
        public DbSet<PerformanceMetric> PerformanceMetrics { get; set; }
        public DbSet<ResourceUsageMetric> ResourceUsageMetrics { get; set; }
        public DbSet<UptimeMetric> UptimeMetrics { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure OAuthClient
            modelBuilder.Entity<OAuthClient>(entity =>
            {
                entity.HasKey(e => e.ClientId);
                entity.Property(e => e.ClientName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Description).HasMaxLength(500);
                
                // Convert Lists to JSON strings for storage
                entity.Property(e => e.RedirectUris)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());
                
                entity.Property(e => e.AllowedGrantTypes)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Deserialize<List<OAuthGrantType>>(v, (JsonSerializerOptions?)null) ?? new List<OAuthGrantType>());
                
                entity.Property(e => e.AllowedScopes)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());
                
                entity.Property(e => e.Properties)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>());
            });

            // Configure Token
            modelBuilder.Entity<Token>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.TokenValue).IsRequired();
                entity.Property(e => e.Name).IsRequired().HasMaxLength(100);
                entity.HasIndex(e => e.TokenValue).IsUnique();
                entity.HasIndex(e => e.UserId);
            });

            // Configure IpLoginAttempt
            modelBuilder.Entity<IpLoginAttempt>(entity =>
            {
                entity.HasKey(e => e.IpAddress);
                entity.Property(e => e.IpAddress).IsRequired().HasMaxLength(45); // IPv6 max length
            });

            // Configure OAuthAuthorizationCode
            modelBuilder.Entity<OAuthAuthorizationCode>(entity =>
            {
                entity.HasKey(e => e.Code);
                entity.Property(e => e.ClientId).IsRequired();
                entity.Property(e => e.UserId).IsRequired();
                entity.Property(e => e.RedirectUri).IsRequired();
                
                entity.Property(e => e.Scopes)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());
                
                entity.HasIndex(e => new { e.ClientId, e.UserId });
                entity.HasIndex(e => e.ExpiresUtc);
            });

            // Configure OAuthAccessToken
            modelBuilder.Entity<OAuthAccessToken>(entity =>
            {
                entity.HasKey(e => e.TokenId);
                entity.Property(e => e.AccessToken).IsRequired();
                entity.Property(e => e.ClientId).IsRequired();
                entity.Property(e => e.UserId).IsRequired();
                
                entity.Property(e => e.Scopes)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());
                
                entity.HasIndex(e => e.AccessToken).IsUnique();
                entity.HasIndex(e => new { e.ClientId, e.UserId });
                entity.HasIndex(e => e.ExpiresUtc);
            });

            // Configure OAuthRefreshToken
            modelBuilder.Entity<OAuthRefreshToken>(entity =>
            {
                entity.HasKey(e => e.TokenId);
                entity.Property(e => e.RefreshToken).IsRequired();
                entity.Property(e => e.AccessTokenId).IsRequired();
                entity.Property(e => e.ClientId).IsRequired();
                entity.Property(e => e.UserId).IsRequired();
                
                entity.Property(e => e.Scopes)
                    .HasConversion(
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());
                
                entity.HasIndex(e => e.RefreshToken).IsUnique();
                entity.HasIndex(e => e.AccessTokenId);
                entity.HasIndex(e => new { e.ClientId, e.UserId });
                entity.HasIndex(e => e.ExpiresUtc);
            });

            // Configure LoginAttemptMetric
            modelBuilder.Entity<LoginAttemptMetric>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.FailureReason).HasMaxLength(100);
                entity.Property(e => e.IpAddress).HasMaxLength(45); // IPv6 max length
                entity.Property(e => e.UserAgent).HasMaxLength(500);
                entity.Property(e => e.Username).HasMaxLength(256);
                
                entity.HasIndex(e => e.Success);
                entity.HasIndex(e => e.CreatedAt);
                entity.HasIndex(e => e.IpAddress);
                entity.HasIndex(e => e.Username);
            });

            // Configure SecurityEventMetric
            modelBuilder.Entity<SecurityEventMetric>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.EventType).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Details).HasMaxLength(1000);
                entity.Property(e => e.IpAddress).HasMaxLength(45); // IPv6 max length
                entity.Property(e => e.Username).HasMaxLength(256);
                
                entity.HasIndex(e => e.EventType);
                entity.HasIndex(e => e.CreatedAt);
                entity.HasIndex(e => e.Severity);
                entity.HasIndex(e => e.IpAddress);
                entity.HasIndex(e => e.Username);
            });

            // Configure ActiveSessionMetric
            modelBuilder.Entity<ActiveSessionMetric>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.CreatedAt);
            });

            // Configure PerformanceMetric
            modelBuilder.Entity<PerformanceMetric>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.OperationType).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Endpoint).HasMaxLength(500);
                entity.Property(e => e.HttpMethod).HasMaxLength(10);
                entity.Property(e => e.UserId).HasMaxLength(256);
                entity.Property(e => e.IpAddress).HasMaxLength(45);
                entity.Property(e => e.UserAgent).HasMaxLength(500);
                
                entity.HasIndex(e => e.OperationType);
                entity.HasIndex(e => e.CreatedAt);
                entity.HasIndex(e => e.Success);
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.ResponseTimeMs);
            });

            // Configure ResourceUsageMetric
            modelBuilder.Entity<ResourceUsageMetric>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.CreatedAt);
            });

            // Configure UptimeMetric
            modelBuilder.Entity<UptimeMetric>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Details).HasMaxLength(500);
                entity.HasIndex(e => e.CreatedAt);
                entity.HasIndex(e => e.IsAvailable);
            });
        }
    }
}