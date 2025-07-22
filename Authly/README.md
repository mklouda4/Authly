# Authly 🔐 - Modern Authentication Server

A modern, containerized authentication server built with ASP.NET Core 8 and Blazor Server. Provides secure authentication with OAuth2 support, TOTP, and comprehensive security features.

## ✨ Features

- 🔒 **Secure Authentication** - User login with password protection and session management
- 🛡️ **Security Features** - User lockout, IP rate limiting, TOTP support, and CSRF protection
- 🌍 **Multi-language Support** - Czech, English, German, French
- 📊 **Monitoring** - Health checks, metrics, and monitoring dashboard
- 🐳 **Docker Ready** - Complete containerization with Docker Compose
- 🔗 **SSO Support** - External authentication endpoints for reverse proxies
- 🚀 **Google OAuth** - Secure Google authentication with PKCE
- 📘 **Facebook OAuth** - Secure Facebook authentication with Graph API
- 🏢 **Microsoft OAuth** - Secure Microsoft/Azure AD authentication
- 🐙 **GitHub OAuth** - Secure GitHub authentication
- 🔑 **TOTP Support** - Two-factor authentication with authenticator apps

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd Authly
```

### 2. Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Edit configuration with your values
nano .env
```

### 3. Start with Docker Compose

```bash
# Start Authly with HealthCheck UI
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### 4. Access the Application

| Service | URL | Description |
|---------|-----|-------------|
| **Authly Application** | http://localhost:8080 | Main authentication service |
| **Health Check UI** | http://localhost:8090/healthchecks-ui | Monitoring dashboard |

### 5. Default Login

> **Default Credentials**
> - **Admin**: `admin` / `admin123`
> - **User**: `user` / `user123`
> 
> ⚠️ **Security Notice**: Change default credentials immediately in production!

## ⚙️ Configuration

### Environment Variables

Configure the application using environment variables in your `.env` file:

```env
# Application Settings
AUTHLY_NAME=My Company Auth
AUTHLY_VERSION=1.0.0
AUTHLY_DEBUG_LOGGING=false
AUTHLY_ENABLE_METRICS=true

# External OAuth Configuration
AUTHLY_ENABLE_GOOGLE=true
AUTHLY_ENABLE_MICROSOFT=true
AUTHLY_ENABLE_GITHUB=true
AUTHLY_ENABLE_FACEBOOK=true

# Google OAuth Credentials
GOOGLE_CLIENT_ID=your-google-client-id.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-google-client-secret

# Microsoft OAuth Credentials
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_TENANT_ID=common

# GitHub OAuth Credentials
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Facebook OAuth Credentials
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret

# User Lockout Security
AUTHLY_USER_LOCKOUT_ENABLED=true
AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3
AUTHLY_USER_LOCKOUT_DURATION=30
AUTHLY_USER_LOCKOUT_SLIDING_WINDOW=true
AUTHLY_USER_LOCKOUT_WINDOW=15

# IP Rate Limiting
AUTHLY_IP_RATE_LIMIT_ENABLED=true
AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5
AUTHLY_IP_RATE_LIMIT_BAN_DURATION=60
AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW=false
AUTHLY_IP_RATE_LIMIT_WINDOW=30

# Network Configuration
HTTP_PORT=8080
HTTPS_PORT=8443
METRICS_PORT=9090
```

### appsettings.json Alternative

```json
{
  "Application": {
    "Name": "Authly",
    "ExternalAuth": {
      "EnableGoogle": true,
      "EnableMicrosoft": true,
      "EnableGitHub": true,
      "EnableFacebook": true
    }
  },
  "Authentication": {
    "Google": {
      "ClientId": "your-google-client-id.googleusercontent.com",
      "ClientSecret": "GOCSPX-your-google-client-secret"
    },
    "Microsoft": {
      "ClientId": "your-microsoft-client-id",
      "ClientSecret": "your-microsoft-client-secret",
      "TenantId": "common"
    },
    "GitHub": {
      "ClientId": "your-github-client-id",
      "ClientSecret": "your-github-client-secret"
    },
    "Facebook": {
      "AppId": "your-facebook-app-id",
      "AppSecret": "your-facebook-app-secret"
    }
  }
}
```

## 🔗 Single Sign-On (SSO)

Authly provides SSO endpoints for seamless integration with reverse proxies and load balancers.

### SSO Endpoints

| Endpoint | Method | Description | Response |
|----------|--------|-------------|----------|
| `/auth` | GET | Authentication verification | `200` (OK) / `401` (Unauthorized) / `403` (Forbidden) |
| `/auth/user` | GET | User information | JSON with user details |
| `/auth/login` | GET | Login redirect | Redirects to login page |

### nginx Configuration

```nginx
server {
    listen 80;
    server_name example.com;

    # Authentication endpoint
    location = /auth {
        internal;
        proxy_pass http://authly:8080/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Protected application
    location / {
        auth_request /auth;
        
        # Pass user information to backend
        auth_request_set $user $upstream_http_x_auth_user;
        auth_request_set $email $upstream_http_x_auth_email;
        auth_request_set $name $upstream_http_x_auth_name;
        auth_request_set $roles $upstream_http_x_auth_roles;
        
        proxy_pass http://your-app:3000;
        proxy_set_header X-Auth-User $user;
        proxy_set_header X-Auth-Email $email;
        proxy_set_header X-Auth-Name $name;
        proxy_set_header X-Auth-Roles $roles;
    }
}
```

### Caddy Configuration

```caddyfile
example.com {
    # Forward authentication to Authly
    forward_auth authly:8080 {
        uri /auth
        copy_headers X-Auth-User X-Auth-Email X-Auth-Name X-Auth-Roles
    }
    
    # Reverse proxy to your application
    reverse_proxy your-app:3000
}
```

### Traefik Configuration

```yaml
# docker-compose.yml for Traefik
version: '3.8'
services:
  traefik:
    image: traefik:v2.10
    command:
      - --providers.docker=true
      - --entrypoints.web.address=:80
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  authly:
    build: .
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.authly.rule=Host(`auth.example.com`)"
      - "traefik.http.services.authly.loadbalancer.server.port=80"

  your-app:
    image: your-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.routers.app.middlewares=authly-auth"
      - "traefik.http.middlewares.authly-auth.forwardauth.address=http://authly:80/auth"
      - "traefik.http.middlewares.authly-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email,X-Auth-Name,X-Auth-Roles"
```

## 🚀 Google OAuth Setup

### Google Cloud Console Configuration

1. **Create Google Cloud Project**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one

2. **Enable OAuth2 API**
   - Go to APIs & Services → Library
   - Enable "Google OAuth2 API"

3. **Create OAuth 2.0 Credentials**
   - Go to APIs & Services → Credentials
   - Click "Create Credentials" → "OAuth 2.0 Client IDs"
   - Select "Web application"

4. **Configure Redirect URIs**
   ```
   # Development
   https://localhost:7283/google/oauth2/callback
   http://localhost:8080/google/oauth2/callback
   
   # Production
   https://your-domain.com/google/oauth2/callback
   ```

5. **Get Credentials**
   - Copy Client ID (format: `xxxxx.apps.googleusercontent.com`)
   - Copy Client Secret (format: `GOCSPX-xxxxx`)

### Security Features

- **PKCE Implementation** - Proof Key for Code Exchange for enhanced security
- **State Validation** - CSRF protection with cryptographically secure state parameters
- **Secure Sessions** - OAuth state stored in secure, HttpOnly session cookies
- **Account Selection** - Forces Google account selection for better UX

## 🏢 Microsoft OAuth Setup

### Azure Active Directory Configuration

1. **Access Azure Portal**
   - Go to [Azure Portal](https://portal.azure.com/)
   - Navigate to Azure Active Directory → App registrations

2. **Create New Application**
   - Click "New registration"
   - **Name**: `Authly`
   - **Supported account types**: "Accounts in any organizational directory and personal Microsoft accounts"

3. **Configure Redirect URIs**
   - **Platform**: Web
   - **Redirect URIs**:
   ```
   # Development
   https://localhost:7283/microsoft/oauth2/callback
   http://localhost:8080/microsoft/oauth2/callback
   
   # Production
   https://your-domain.com/microsoft/oauth2/callback
   ```

4. **Create Client Secret**
   - Go to Certificates & secrets → Client secrets
   - Click "New client secret"
   - Set expiration (recommended: 24 months)
   - **Copy the secret value immediately**

5. **Set API Permissions**
   - Go to API permissions
   - Ensure these permissions are present:
     - `openid`
     - `profile`
     - `email`
     - `User.Read`

6. **Get Credentials**
   - Copy **Application (client) ID**
   - Copy **Client secret value**
   - Copy **Directory (tenant) ID** (optional)

### Microsoft Configuration Options

```env
# Multi-tenant (personal + work accounts)
MICROSOFT_TENANT_ID=common

# Work/school accounts only
MICROSOFT_TENANT_ID=organizations

# Personal Microsoft accounts only
MICROSOFT_TENANT_ID=consumers

# Specific organization only
MICROSOFT_TENANT_ID=your-tenant-id
```

## 🐙 GitHub OAuth Setup

### GitHub Developer Portal Configuration

1. **Access GitHub Settings**
   - Go to [GitHub](https://github.com/) → Settings → Developer settings
   - Click "OAuth Apps" → "New OAuth App"

2. **Create OAuth Application**
   - **Application name**: `Authly`
   - **Homepage URL**: `https://your-domain.com` (or `http://localhost:8080` for development)
   - **Application description**: Optional description
   - **Authorization callback URL**:
   ```
   # Development
   https://localhost:7283/github/oauth2/callback
   http://localhost:8080/github/oauth2/callback
   
   # Production
   https://your-domain.com/github/oauth2/callback
   ```

3. **Get Credentials**
   - Copy **Client ID**
   - Click "Generate a new client secret"
   - **Copy the client secret immediately**

### GitHub OAuth Scopes

Authly requests these scopes:
- `user:email` - Access to user's email addresses
- `read:user` - Read access to user profile information

### Security Features

- **PKCE Implementation** - Enhanced security with code challenge
- **Email Verification** - Handles both public and private email scenarios
- **State Validation** - CSRF protection
- **Fallback Email** - Creates fallback email for users without public email

## 📘 Facebook OAuth Setup

### Facebook Developer Portal Configuration

1. **Create Facebook App**
   - Go to [Facebook for Developers](https://developers.facebook.com/)
   - Click "Create App" and select "Consumer" use case
   - Enter App Display Name and Contact Email

2. **Add Facebook Login Product**
   - In your app dashboard, click "Add Product"
   - Find "Facebook Login" and click "Set Up"
   - Select "Web" platform

3. **Configure OAuth Settings**
   - Go to Facebook Login → Settings
   - Add Valid OAuth Redirect URIs:
   ```
   # Development
   https://localhost:7283/facebook/oauth2/callback
   http://localhost:8080/facebook/oauth2/callback
   
   # Production
   https://your-domain.com/facebook/oauth2/callback
   ```

4. **Configure App Settings**
   - Go to Settings → Basic
   - Add App Domains (e.g., `localhost` for development)
   - Set Privacy Policy URL and Terms of Service URL

5. **Get App Credentials**
   - Copy **App ID** (numeric identifier)
   - Copy **App Secret** (click "Show" to reveal)

### Security Features

- **State Validation** - CSRF protection with secure state parameters
- **Graph API v18.0** - Latest Facebook Graph API version
- **Email Verification** - Facebook-verified emails are trusted
- **Account Re-authentication** - Forces account selection when needed

## 🛡️ Security Features

### Authentication Security

- **Password Hashing** - BCrypt with configurable work factor
- **Session Management** - Secure cookie-based sessions with HTTPS enforcement
- **CSRF Protection** - Anti-forgery tokens and state validation
- **OAuth Security** - PKCE for Google/GitHub/Microsoft, state validation for all providers
- **IP Protection** - Comprehensive IP-based security for all authentication methods

### Brute Force Protection

```env
# User Lockout Configuration
AUTHLY_USER_LOCKOUT_ENABLED=true
AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3      # Failed attempts before lockout
AUTHLY_USER_LOCKOUT_DURATION=30         # Lockout duration in minutes
AUTHLY_USER_LOCKOUT_SLIDING_WINDOW=true # Reset attempts over time
AUTHLY_USER_LOCKOUT_WINDOW=15           # Time window for sliding window

# IP Rate Limiting Configuration
AUTHLY_IP_RATE_LIMIT_ENABLED=true
AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5     # Attempts per IP
AUTHLY_IP_RATE_LIMIT_BAN_DURATION=60    # Ban duration in minutes
AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW=false # Use fixed window
AUTHLY_IP_RATE_LIMIT_WINDOW=30          # Time window in minutes
```

### Two-Factor Authentication (TOTP)

- **Google Authenticator** compatible
- **Microsoft Authenticator** compatible
- **QR Code generation** for easy setup
- **Backup codes** for account recovery
- **Configurable validity window**

## 📊 Monitoring & Health Checks

### Health Check Endpoints

| Endpoint | Description | Use Case |
|----------|-------------|----------|
| `/health` | Overall application health | Load balancer health checks |
| `/health/ready` | Readiness probe | Kubernetes readiness probe |
| `/health/live` | Liveness probe | Kubernetes liveness probe |
| `/healthchecks-ui` | Visual health dashboard | Monitoring dashboard |

### Health Check Commands

```bash
# Check application health
curl http://localhost:8080/health

# Check readiness
curl http://localhost:8080/health/ready

# Check liveness
curl http://localhost:8080/health/live

# View health dashboard
open http://localhost:8090/healthchecks-ui
```

### Metrics (Optional)

When `AUTHLY_ENABLE_METRICS=true`, Prometheus-compatible metrics are available:

```bash
# Prometheus-compatible metrics
curl http://localhost:8080/metrics
```

**Available Metrics:**
- Login attempts (successful/failed)
- External OAuth attempts (Google, Microsoft, GitHub, Facebook)
- User lockout events
- IP ban events
- Request duration
- Active sessions

## 💾 Data Persistence

User data is stored in the `./data` directory with automatic persistence:

```
./data/
├── users.json          # User accounts and profiles
├── ip-bans.json        # IP ban records and timestamps
└── sessions.json       # Active user sessions (optional)
```

**Data Features:**
- Automatic backup on changes
- JSON format for easy inspection
- Persists across container restarts
- Configurable data retention

## 🔧 Development

### Running Locally

```bash
# Restore packages
dotnet restore

# Run in development mode
dotnet run --project Authly

# Access at https://localhost:7283
```

### Building

```bash
# Build application
dotnet build -c Release

# Run tests
dotnet test

# Build Docker image
docker build -t authly:latest .

# Build with version tag
docker build -t authly:1.0.0 .
```

### Development Environment

```bash
# Start with development overrides
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Enable debug logging
export AUTHLY_DEBUG_LOGGING=true
docker-compose up
```

## 🔍 API Reference

### Authentication Headers

When successfully authenticated, Authly provides these headers:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Auth-User` | Username | `john.doe` |
| `X-Auth-Email` | Email address | `john@example.com` |
| `X-Auth-Name` | Display name | `John Doe` |
| `X-Auth-Roles` | User roles (comma-separated) | `admin,user` |
| `X-Auth-Authenticated` | Authentication status | `true` |
| `X-Auth-External` | External authentication flag | `true` (for OAuth users) |

### Response Codes

| Code | Status | Description |
|------|--------|-------------|
| `200` | OK | User is authenticated |
| `401` | Unauthorized | User not logged in |
| `403` | Forbidden | User account locked/banned |
| `429` | Too Many Requests | Rate limit exceeded |

### OAuth Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/google-login` | GET | Initiate Google OAuth flow |
| `/google/oauth2/callback` | GET | Google OAuth callback |
| `/microsoft-login` | GET | Initiate Microsoft OAuth flow |
| `/microsoft/oauth2/callback` | GET | Microsoft OAuth callback |
| `/github-login` | GET | Initiate GitHub OAuth flow |
| `/github/oauth2/callback` | GET | GitHub OAuth callback |
| `/facebook-login` | GET | Initiate Facebook OAuth flow |
| `/facebook/oauth2/callback` | GET | Facebook OAuth callback |

## 🚨 Troubleshooting

### Common Issues

#### Port Conflicts

```bash
# Check if ports are in use
netstat -tulpn | grep :8080
netstat -tulpn | grep :8090

# Use different ports
export HTTP_PORT=8081
export METRICS_PORT=9091
docker-compose up
```

#### OAuth Configuration Issues

```bash
# Check OAuth configuration
echo $AUTHLY_ENABLE_GOOGLE     # Should be 'true'
echo $AUTHLY_ENABLE_MICROSOFT  # Should be 'true'
echo $AUTHLY_ENABLE_GITHUB     # Should be 'true'
echo $AUTHLY_ENABLE_FACEBOOK   # Should be 'true'

echo $GOOGLE_CLIENT_ID         # Should not be empty
echo $MICROSOFT_CLIENT_ID      # Should not be empty
echo $GITHUB_CLIENT_ID         # Should not be empty
echo $FACEBOOK_APP_ID          # Should not be empty

# Verify in application logs
docker-compose logs authly | grep -E "(GoogleLogin|MicrosoftLogin|GitHubLogin|FacebookLogin).*disabled"
```

#### Data Permission Issues

```bash
# Fix data directory permissions
sudo chown -R $USER:$USER ./data
chmod 755 ./data

# Or use Docker volume
docker volume create authly-data
```

### Debug Commands

```bash
# Container status and resource usage
docker-compose ps
docker stats

# Detailed logs with timestamps
docker-compose logs -f --timestamps authly

# Execute commands in container
docker-compose exec authly /bin/bash

# Test authentication endpoints
curl -I http://localhost:8080/auth
curl http://localhost:8080/auth/user

# Network connectivity
docker-compose exec authly curl http://localhost:80/health
```

### OAuth Debugging

```bash
# Enable detailed OAuth logging
export AUTHLY_DEBUG_LOGGING=true
docker-compose up

# Monitor OAuth flows
docker-compose logs -f authly | grep -E "(GoogleLogin|GoogleOAuth|MicrosoftLogin|MicrosoftOAuth|GitHubLogin|GitHubOAuth|FacebookLogin|FacebookOAuth)"

# Check for specific errors
docker-compose logs authly | grep -E "(ERROR|WARN)" | grep -iE "(google|microsoft|github|facebook)"
```

### OAuth Provider Testing

```bash
# Test Google OAuth
curl -I "http://localhost:8080/google-login"

# Test Microsoft OAuth
curl -I "http://localhost:8080/microsoft-login"

# Test GitHub OAuth
curl -I "http://localhost:8080/github-login"

# Test Facebook OAuth
curl -I "http://localhost:8080/facebook-login"
```

## 🤝 Support

### Getting Help

1. **Check the logs** first: `docker-compose logs authly`
2. **Review configuration** in `.env` file
3. **Test health endpoints** to verify service status
4. **Check GitHub Issues** for known problems

### Reporting Issues

When reporting issues, please include:
- Docker Compose logs
- Configuration (without sensitive data)
- Steps to reproduce
- Expected vs actual behavior
- OAuth-specific details if applicable

---

**License**: MIT  
**Author**: Built with ❤️ for secure authentication