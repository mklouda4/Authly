using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Authly.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Vytvoření tabulek s IF NOT EXISTS
            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS ActiveSessionMetrics (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    SessionCount INTEGER NOT NULL,
                    CreatedAt TEXT NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS IpLoginAttempts (
                    IpAddress TEXT PRIMARY KEY,
                    FailedAttempts INTEGER NOT NULL,
                    FirstAttemptUtc TEXT NOT NULL,
                    LastAttemptUtc TEXT NOT NULL,
                    IsBanned INTEGER NOT NULL,
                    BanEndUtc TEXT
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS LoginAttemptMetrics (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Success INTEGER NOT NULL,
                    FailureReason TEXT,
                    IpAddress TEXT,
                    UserAgent TEXT,
                    Username TEXT,
                    ResponseTimeMs REAL,
                    CreatedAt TEXT NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS OAuthAccessTokens (
                    TokenId TEXT PRIMARY KEY,
                    AccessToken TEXT NOT NULL,
                    ClientId TEXT NOT NULL,
                    UserId TEXT NOT NULL,
                    Scopes TEXT NOT NULL,
                    CreatedUtc TEXT NOT NULL,
                    ExpiresUtc TEXT NOT NULL,
                    IsRevoked INTEGER NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS OAuthAuthorizationCodes (
                    Code TEXT PRIMARY KEY,
                    ClientId TEXT NOT NULL,
                    UserId TEXT NOT NULL,
                    RedirectUri TEXT NOT NULL,
                    Scopes TEXT NOT NULL,
                    CodeChallenge TEXT,
                    CodeChallengeMethod TEXT,
                    Nonce TEXT,
                    CreatedUtc TEXT NOT NULL,
                    ExpiresUtc TEXT NOT NULL,
                    IsUsed INTEGER NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS OAuthClients (
                    ClientId TEXT PRIMARY KEY,
                    ClientSecret TEXT,
                    ClientName TEXT NOT NULL,
                    Description TEXT,
                    ClientType INTEGER NOT NULL,
                    RedirectUris TEXT NOT NULL,
                    AllowedGrantTypes TEXT NOT NULL,
                    AllowedScopes TEXT NOT NULL,
                    AccessTokenLifetime INTEGER NOT NULL,
                    RefreshTokenLifetime INTEGER,
                    RequirePkce INTEGER NOT NULL,
                    AllowPlainTextPkce INTEGER NOT NULL,
                    LogoUri TEXT,
                    ClientUri TEXT,
                    TosUri TEXT,
                    PolicyUri TEXT,
                    CreatedUtc TEXT NOT NULL,
                    ModifiedUtc TEXT NOT NULL,
                    Enabled INTEGER NOT NULL,
                    CreatedBy TEXT,
                    Properties TEXT NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS OAuthRefreshTokens (
                    TokenId TEXT PRIMARY KEY,
                    RefreshToken TEXT NOT NULL,
                    AccessTokenId TEXT NOT NULL,
                    ClientId TEXT NOT NULL,
                    UserId TEXT NOT NULL,
                    Scopes TEXT NOT NULL,
                    CreatedUtc TEXT NOT NULL,
                    ExpiresUtc TEXT NOT NULL,
                    IsRevoked INTEGER NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS PerformanceMetrics (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    OperationType TEXT NOT NULL,
                    Endpoint TEXT,
                    HttpMethod TEXT,
                    ResponseTimeMs REAL NOT NULL,
                    Success INTEGER NOT NULL,
                    StatusCode INTEGER,
                    RequestSizeBytes INTEGER,
                    ResponseSizeBytes INTEGER,
                    UserId TEXT,
                    IpAddress TEXT,
                    UserAgent TEXT,
                    CreatedAt TEXT NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS ResourceUsageMetrics (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    CpuUsagePercent REAL NOT NULL,
                    MemoryUsageMB REAL NOT NULL,
                    TotalMemoryMB REAL NOT NULL,
                    ActiveThreads INTEGER NOT NULL,
                    ActiveDbConnections INTEGER,
                    CreatedAt TEXT NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS SecurityEventMetrics (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    EventType TEXT NOT NULL,
                    Details TEXT,
                    IpAddress TEXT,
                    Username TEXT,
                    Severity INTEGER NOT NULL,
                    CreatedAt TEXT NOT NULL
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS Tokens (
                    Id TEXT PRIMARY KEY,
                    UserId TEXT NOT NULL,
                    TokenValue TEXT NOT NULL,
                    Name TEXT NOT NULL,
                    CreatedUtc TEXT NOT NULL,
                    LastUsedUtc TEXT,
                    ExpiresUtc TEXT,
                    IsActive INTEGER NOT NULL,
                    CreatedFromIp TEXT,
                    CreatedFromUserAgent TEXT,
                    Scopes TEXT
                );
            ");

            migrationBuilder.Sql(@"
                CREATE TABLE IF NOT EXISTS UptimeMetrics (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    IsAvailable INTEGER NOT NULL,
                    HealthCheckResponseTimeMs REAL,
                    Details TEXT,
                    CreatedAt TEXT NOT NULL
                );
            ");

            // Vytvoření indexů s IF NOT EXISTS
            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_ActiveSessionMetrics_CreatedAt 
                ON ActiveSessionMetrics(CreatedAt);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_LoginAttemptMetrics_CreatedAt 
                ON LoginAttemptMetrics(CreatedAt);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_LoginAttemptMetrics_IpAddress 
                ON LoginAttemptMetrics(IpAddress);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_LoginAttemptMetrics_Success 
                ON LoginAttemptMetrics(Success);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_LoginAttemptMetrics_Username 
                ON LoginAttemptMetrics(Username);
            ");

            migrationBuilder.Sql(@"
                CREATE UNIQUE INDEX IF NOT EXISTS IX_OAuthAccessTokens_AccessToken 
                ON OAuthAccessTokens(AccessToken);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_OAuthAccessTokens_ClientId_UserId 
                ON OAuthAccessTokens(ClientId, UserId);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_OAuthAccessTokens_ExpiresUtc 
                ON OAuthAccessTokens(ExpiresUtc);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_OAuthAuthorizationCodes_ClientId_UserId 
                ON OAuthAuthorizationCodes(ClientId, UserId);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_OAuthAuthorizationCodes_ExpiresUtc 
                ON OAuthAuthorizationCodes(ExpiresUtc);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_OAuthRefreshTokens_AccessTokenId 
                ON OAuthRefreshTokens(AccessTokenId);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_OAuthRefreshTokens_ClientId_UserId 
                ON OAuthRefreshTokens(ClientId, UserId);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_OAuthRefreshTokens_ExpiresUtc 
                ON OAuthRefreshTokens(ExpiresUtc);
            ");

            migrationBuilder.Sql(@"
                CREATE UNIQUE INDEX IF NOT EXISTS IX_OAuthRefreshTokens_RefreshToken 
                ON OAuthRefreshTokens(RefreshToken);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_PerformanceMetrics_CreatedAt 
                ON PerformanceMetrics(CreatedAt);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_PerformanceMetrics_OperationType 
                ON PerformanceMetrics(OperationType);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_PerformanceMetrics_ResponseTimeMs 
                ON PerformanceMetrics(ResponseTimeMs);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_PerformanceMetrics_Success 
                ON PerformanceMetrics(Success);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_PerformanceMetrics_UserId 
                ON PerformanceMetrics(UserId);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_ResourceUsageMetrics_CreatedAt 
                ON ResourceUsageMetrics(CreatedAt);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_SecurityEventMetrics_CreatedAt 
                ON SecurityEventMetrics(CreatedAt);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_SecurityEventMetrics_EventType 
                ON SecurityEventMetrics(EventType);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_SecurityEventMetrics_IpAddress 
                ON SecurityEventMetrics(IpAddress);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_SecurityEventMetrics_Severity 
                ON SecurityEventMetrics(Severity);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_SecurityEventMetrics_Username 
                ON SecurityEventMetrics(Username);
            ");

            migrationBuilder.Sql(@"
                CREATE UNIQUE INDEX IF NOT EXISTS IX_Tokens_TokenValue 
                ON Tokens(TokenValue);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_Tokens_UserId 
                ON Tokens(UserId);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_UptimeMetrics_CreatedAt 
                ON UptimeMetrics(CreatedAt);
            ");

            migrationBuilder.Sql(@"
                CREATE INDEX IF NOT EXISTS IX_UptimeMetrics_IsAvailable 
                ON UptimeMetrics(IsAvailable);
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TABLE IF EXISTS ActiveSessionMetrics;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS IpLoginAttempts;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS LoginAttemptMetrics;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS OAuthAccessTokens;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS OAuthAuthorizationCodes;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS OAuthClients;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS OAuthRefreshTokens;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS PerformanceMetrics;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS ResourceUsageMetrics;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS SecurityEventMetrics;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS Tokens;");
            migrationBuilder.Sql("DROP TABLE IF EXISTS UptimeMetrics;");
        }
    }
}