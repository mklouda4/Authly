# Authly 🔐 - Modern Authentication Server

A modern, containerized authentication server built with ASP.NET Core 8 and Blazor Server. Provides secure authentication with OAuth2 support, TOTP, comprehensive security features, and a powerful admin panel for system management.

## ✨ Features

- 🔒 **Secure Authentication** - User login with password protection and session management
- 🛡️ **Security Features** - User lockout, IP rate limiting, TOTP support, and CSRF protection
- 🌍 **Multi-language Support** - Czech, English, German, French
- 📊 **Monitoring** - Health checks, metrics, and monitoring dashboard
- 🐳 **Docker Ready** - Complete containerization with pre-built images
- 🔗 **SSO Support** - External authentication endpoints for reverse proxies
- 🚀 **Google OAuth** - Secure Google authentication with PKCE
- 📘 **Facebook OAuth** - Secure Facebook authentication with Graph API
- 🏢 **Microsoft OAuth** - Secure Microsoft/Azure AD authentication
- 🐙 **GitHub OAuth** - Secure GitHub authentication
- 🔑 **TOTP Support** - Two-factor authentication with authenticator apps
- 🎛️ **Admin Panel** - Comprehensive administration interface for user and system management
- 📡 **MQTT Support** - Publish events to MQTT broker

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
# Pull the latest image and start Authly with HealthCheck UI
docker-compose pull
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

### Complete Environment Variables Reference

Configure the application using environment variables in your `.env` file:

```bash
# ===== Application Settings =====
AUTHLY_NAME=My Company Auth                    # Application display name
AUTHLY_DOMAIN=example.com                      # Domain for cookie scope
AUTHLY_BASE_URL=https://auth.example.com       # Base URL for redirects
AUTHLY_VERSION=1.0.0                          # Application version
AUTHLY_DEBUG_LOGGING=false                    # Enable detailed debug logging
AUTHLY_ENABLE_METRICS=true                    # Enable Prometheus metrics
AUTHLY_ALLOW_REGISTRATION=false               # Allow permanent user registration
AUTHLY_KEY_DIRECTORY=/app/keys                 # Directory for data protection keys

# ===== External OAuth Enable/Disable =====
AUTHLY_ENABLE_GOOGLE=true                     # Enable Google OAuth
AUTHLY_ENABLE_MICROSOFT=true                  # Enable Microsoft OAuth
AUTHLY_ENABLE_GITHUB=true                     # Enable GitHub OAuth
AUTHLY_ENABLE_FACEBOOK=true                   # Enable Facebook OAuth

# ===== Google OAuth Credentials =====
GOOGLE_CLIENT_ID=your-google-client-id.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-google-client-secret

# ===== Microsoft OAuth Credentials =====
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_TENANT_ID=common                    # common, organizations, consumers, or specific tenant ID

# ===== GitHub OAuth Credentials =====
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# ===== Facebook OAuth Credentials =====
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret

# ===== User Lockout Security =====
AUTHLY_USER_LOCKOUT_ENABLED=true              # Enable user account lockout
AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3            # Failed attempts before lockout
AUTHLY_USER_LOCKOUT_DURATION=30               # Lockout duration in minutes
AUTHLY_USER_LOCKOUT_SLIDING_WINDOW=true       # Use sliding window for attempts
AUTHLY_USER_LOCKOUT_WINDOW=15                 # Time window for sliding window (minutes)

# ===== IP Rate Limiting =====
AUTHLY_IP_RATE_LIMIT_ENABLED=true             # Enable IP-based rate limiting
AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5           # Max attempts per IP
AUTHLY_IP_RATE_LIMIT_BAN_DURATION=60          # IP ban duration in minutes
AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW=false     # Use fixed window for IP limits
AUTHLY_IP_RATE_LIMIT_WINDOW=30                # Time window for IP limits (minutes)

# ===== Network Configuration =====
HTTP_PORT=8080                                 # HTTP port for container
HTTPS_PORT=8443                                # HTTPS port for container
METRICS_PORT=9090                              # Metrics port for monitoring

# ===== MQTT Integration =====
AUTHLY_MQTT_ENABLED=false                     # Enable MQTT client integration

# Connection Method (choose ONE):
AUTHLY_MQTT_WEBSOCKET_URI=ws://localhost:8083/mqtt  # WebSocket URI - takes PRIORITY over TCP
# OR
AUTHLY_MQTT_SERVER=localhost                  # MQTT broker hostname (used only if WebSocket URI is empty)
AUTHLY_MQTT_PORT=1883                         # MQTT broker port (1883 for non-TLS, 8883 for TLS)
AUTHLY_MQTT_USE_TLS=false                     # Enable TLS/SSL encryption for TCP connection

# Authentication & Client Settings:
AUTHLY_MQTT_CLIENT_ID=authly-server-001       # Unique client identifier for MQTT connection
AUTHLY_MQTT_USERNAME=mqtt_user                # Username for MQTT broker authentication (optional)
AUTHLY_MQTT_PASSWORD=mqtt_password            # Password for MQTT broker authentication (optional)
AUTHLY_MQTT_KEEP_ALIVE_SECONDS=60             # Keep-alive interval in seconds (default: 60)
```

### appsettings.json Alternative

If you prefer configuration files over environment variables:

```json
{
  "Application": {
    "Name": "Authly",
    "Domain": "example.com",
    "BaseUrl": "https://auth.example.com",
    "Version": "1.0.0",
    "DebugLogging": false,
    "EnableMetrics": true,
    "AllowRegistration": false,
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
  },
  "Security": {
    "UserLockout": {
      "Enabled": true,
      "MaxFailedAttempts": 3,
      "LockoutDurationMinutes": 30,
      "SlidingWindow": true,
      "WindowMinutes": 15
    },
    "IpRateLimit": {
      "Enabled": true,
      "MaxAttemptsPerIp": 5,
      "BanDurationMinutes": 60,
      "SlidingWindow": false,
      "WindowMinutes": 30
    }
  },
  "Mqtt": {
    "Enabled": false,
    "WebSocketUri": "ws://localhost:8083/mqtt",
    "Server": "localhost",
    "Port": 1883,
    "UseTls": false,
    "ClientId": "authly-server-001",
    "Username": "mqtt_user",
    "Password": "mqtt_password",
    "KeepAliveSeconds": 60
  }
}
```

## 🐳 Docker Image

```bash
Authly is available as a pre-built Docker image from GitHub Container Registry:
# Pull the latest image
docker pull ghcr.io/mklouda4/authly:latest

# Run standalone container
docker run -d \
  --name authly-app \
  -p 8080:80 \
  -p 9090:9090 \
  -v authly_data:/app/wwwroot/data \
  -v authly_keys:/app/wwwroot/keys \
  -e AUTHLY_NAME="My Company Auth" \
  -e AUTHLY_DOMAIN=your-domain.com \
  -e AUTHLY_BASE_URL=https://auth.your-domain.com \
  --restart unless-stopped \
  ghcr.io/mklouda4/authly:latest
```

### Available Tags

| Tag | Description | Use Case |
|-----|-------------|----------|
| `latest` | Latest stable release | Production deployments |
| `v1.0.0` | Specific version | Production with version pinning |
| `develop` | Development builds | Testing and development |

### Image Information

- **Base Image**: mcr.microsoft.com/dotnet/aspnet:8.0
- **Architecture**: linux/amd64, linux/arm64
- **Size**: ~200MB
- **Registry**: GitHub Container Registry (ghcr.io)

## 🎛️ Admin Panel

Authly features a comprehensive admin panel available at `/admin` for administrators to manage users, security, and system configuration.

### Access Requirements

- **Administrator privileges** required
- **Secure authentication** with active session
- **Multi-tab interface** with persistent state

### Admin Panel Features

#### 👥 User Management
- **View all users** with detailed information
- **User status monitoring** (active, locked, admin)
- **TOTP status** for each user
- **Failed login attempts** tracking
- **User account actions**:
  - Unlock locked accounts
  - Reset failed login attempts
  - Toggle administrator privileges
  - Delete user accounts
  - View detailed user information

#### 🛡️ IP Management
- **Monitor banned IPs** with detailed ban information
- **View failed attempts** per IP address
- **Ban status tracking** with expiration times
- **IP management actions**:
  - Manually unban IP addresses
  - View attempt history
  - Monitor current ban status
  - Clear IP ban records

#### 🔑 Token Management
- **Long-lived token oversight** for external authentication
- **Active token monitoring** per user
- **Token lifecycle management**:
  - View active tokens
  - Revoke user tokens
  - Monitor token usage
  - Clean expired tokens

#### 📄 OAuth Client Management
- **OAuth client configuration** and monitoring
- **Client credential management**
- **Authorization tracking**:
  - View registered clients
  - Monitor client activity
  - Manage client permissions
  - Audit OAuth flows

#### ⚙️ Application Settings
- **Registration controls**:
  - **Permanent registration** - Enable/disable new user registration
  - **Temporary registration** - Time-limited registration windows
  - **Registration status** - Current system state
- **Real-time countdown** for temporary registration
- **Dynamic configuration** updates

#### 📋 System Logs
- **Real-time log monitoring** - View latest system activity
- **Last 50 log entries** - Recent application logs and events
- **Log level filtering** - Filter by severity (Error, Warning, Info, Debug)
- **Log management features**:
  - View detailed log messages
  - Monitor system health in real-time
  - Track authentication events
  - Debug application issues
  - Export log data

### Admin Panel Navigation

The admin panel features a tabbed interface with persistent state:

```
/admin
├── User Management     - Manage user accounts and permissions
├── IP Management      - Monitor and control IP-based security
├── Token Management   - Oversee OAuth and access tokens
├── OAuth Clients      - Manage external OAuth client applications
├── System Logs        - View recent application logs (last 50 entries)
└── Application Settings - Configure system-wide settings
```

### Admin Panel Security

- **Role-based access** - Only administrator accounts can access
- **Session validation** - Active authentication required
- **CSRF protection** - Anti-forgery tokens on all forms
- **Real-time updates** - Live data refresh and notifications

### Admin Capabilities

| Feature | Description | Actions Available |
|---------|-------------|------------------|
| **User Accounts** | Complete user lifecycle management | View, Edit, Lock/Unlock, Delete, Promote/Demote |
| **Security Monitoring** | Track security events and threats | Monitor attempts, Manage bans, View patterns |
| **System Configuration** | Control application behavior | Enable/disable features, Set timeouts, Configure limits |
| **OAuth Management** | Oversee external authentication | Monitor tokens, Revoke access, Audit clients |
| **Registration Control** | Manage new user registration | Enable permanently, Enable temporarily, Monitor status |
| **System Logs** | Monitor application logs and events | View logs, Filter by level, Track system health |

### System Log Monitoring

The admin panel includes a dedicated **System Logs** tab that provides real-time access to application logs for debugging and monitoring purposes.

#### Log Features

- **Recent Activity** - Displays the **last 50 log entries** in reverse chronological order
- **Real-time Updates** - Logs automatically refresh for live monitoring
- **Log Level Indicators** - Color-coded severity levels for quick identification
- **Detailed Information** - Full log messages with timestamps and context

#### Log Levels

| Level | Description | Color Indicator |
|-------|-------------|----------------|
| **Error** | Application errors and exceptions | 🔴 Red |
| **Warning** | Warning messages and potential issues | 🟡 Yellow |
| **Information** | General application information | 🔵 Blue |
| **Debug** | Detailed debugging information | 🟢 Green |

#### Log Entry Information

Each log entry displays:
- **Timestamp** - When the event occurred
- **Log Level** - Severity of the message
- **Category** - Component or module that generated the log  
- **Message** - Detailed log message
- **Exception Details** - Stack traces for errors (when applicable)

#### Common Log Categories

- `Authly.Services.AuthenticationService` - User authentication events
- `Authly.Services.OAuthService` - OAuth provider interactions
- `Authly.Services.SecurityService` - Security events and lockouts
- `Microsoft.AspNetCore.Authentication` - ASP.NET Core authentication
- `System.Net.Http.HttpClient` - HTTP client requests
- `Authly.Services.MqttService` - MQTT integration events

#### Using System Logs for Troubleshooting

**Authentication Issues:**
```
Look for entries from:
- Authly.Services.AuthenticationService
- Microsoft.AspNetCore.Authentication.*
- Failed login attempts and lockout events
```

**OAuth Problems:**
```
Monitor logs from:
- Authly.Services.OAuthService  
- GoogleLogin, MicrosoftLogin, GitHubLogin, FacebookLogin
- OAuth callback and token exchange errors
```

**MQTT Integration:**
```
Check entries from:
- Authly.Services.MqttService
- Connection status and publishing events
- MQTT broker communication errors
```

**System Performance:**
```
Review logs for:
- High request volumes
- Slow response times
- Resource utilization warnings
- Health check failures
```

#### Log Best Practices

- **Regular Monitoring** - Check logs periodically for errors or warnings
- **Pattern Recognition** - Identify recurring issues or attack patterns
- **Correlation** - Match log entries with user reports or system behavior
- **Documentation** - Use logs to document and resolve issues

> **💡 Tip**: The System Logs tab is particularly useful for real-time debugging during development and for monitoring production systems for unusual activity.

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
        proxy_pass http://authly-ip-address/api/authz/forward-auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Cookie $http_cookie;
    }

    # Protected application
    location / {
        auth_request /auth;
        
        # Pass user information to backend (both X-Auth-* and Remote-* headers)
        auth_request_set $user $upstream_http_x_auth_user;
        auth_request_set $email $upstream_http_x_auth_email;
        auth_request_set $name $upstream_http_x_auth_name;
        auth_request_set $user_id $upstream_http_x_auth_userid;
        auth_request_set $roles $upstream_http_x_auth_roles;
        auth_request_set $method $upstream_http_x_auth_method;
        auth_request_set $is_admin $upstream_http_x_auth_isadmin;
        auth_request_set $has_totp $upstream_http_x_auth_hastotp;
        
        # Remote-* headers (for compatibility)
        auth_request_set $remote_user $upstream_http_remote_user;
        auth_request_set $remote_email $upstream_http_remote_email;
        auth_request_set $remote_name $upstream_http_remote_name;
        auth_request_set $remote_groups $upstream_http_remote_groups;
        auth_request_set $remote_userid $upstream_http_remote_userid;
        
        proxy_pass http://your-app:3000;
        
        # Forward X-Auth-* headers
        proxy_set_header X-Auth-User $user;
        proxy_set_header X-Auth-Email $email;
        proxy_set_header X-Auth-Name $name;
        proxy_set_header X-Auth-UserId $user_id;
        proxy_set_header X-Auth-Roles $roles;
        proxy_set_header X-Auth-Method $method;
        proxy_set_header X-Auth-IsAdmin $is_admin;
        proxy_set_header X-Auth-HasTotp $has_totp;
        
        # Forward Remote-* headers (for compatibility)
        proxy_set_header Remote-User $remote_user;
        proxy_set_header Remote-Email $remote_email;
        proxy_set_header Remote-Name $remote_name;
        proxy_set_header Remote-Groups $remote_groups;
        proxy_set_header Remote-UserId $remote_userid;
        
        # Standard proxy headers
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Redirect to login on authentication failure
    error_page 401 = @error401;
    location @error401 {
        return 302 http://authly-ip-address/login?returnUrl=$scheme://$http_host$request_uri;
    }
    
    # Handle forbidden access
    error_page 403 = @error403;
    location @error403 {
        return 302 http://authly-ip-address/login?error=access_denied&returnUrl=$scheme://$http_host$request_uri;
    }
}

# Authly login server (can be on different subdomain)
server {
    listen 80;
    server_name auth.example.com;

    location / {
        proxy_pass http://authly-ip-address;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Alternative with Docker service name (if in same network)
server {
    listen 80;
    server_name example.com;

    location = /auth {
        internal;
        proxy_pass http://authly:8088/api/authz/forward-auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header Cookie $http_cookie;
    }

    location / {
        auth_request /auth;
        # ... same header configuration as above
        proxy_pass http://your-app:3000;
    }
}
```

### Caddy Configuration

```caddy
# Protected application
example.com {
    # Forward authentication to Authly
    forward_auth http://authly-ip-address {
        uri /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
        header_up Cookie {http.request.header.Cookie}
        header_up X-Original-URL {http.request.orig_uri}
        header_up X-Original-Method {http.request.method}
    }
    
    # Proxy to your application
    reverse_proxy your-app:3000
}

# Authly authentication server
auth.example.com {
    reverse_proxy http://authly-ip-address
}

# Alternative with Docker service name (if in same network)
example.com {
    forward_auth authly:8088 {
        uri /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
        header_up Cookie {http.request.header.Cookie}
        header_up X-Original-URL {http.request.orig_uri}
        header_up X-Original-Method {http.request.method}
    }
    
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
    image: ghcr.io/mklouda4/authly:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.authly.rule=Host(`auth.example.com`)"
      - "traefik.http.services.authly.loadbalancer.server.port=8088"

  your-app:
    image: your-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.routers.app.middlewares=authly-auth"
      - "traefik.http.middlewares.authly-auth.forwardauth.address=http://authly:8088/api/authz/forward-auth"
      - "traefik.http.middlewares.authly-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email,X-Auth-Name,X-Auth-UserId,X-Auth-Roles,X-Auth-Method,X-Auth-IsAdmin,X-Auth-HasTotp,Remote-User,Remote-Email,Remote-Name,Remote-Groups,Remote-UserId"

# Alternative with external Authly instance
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

  your-app:
    image: your-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.routers.app.middlewares=authly-auth"
      - "traefik.http.middlewares.authly-auth.forwardauth.address=http://authly-ip-address/api/authz/forward-auth"
      - "traefik.http.middlewares.authly-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email,X-Auth-Name,X-Auth-UserId,X-Auth-Roles,X-Auth-Method,X-Auth-IsAdmin,X-Auth-HasTotp,Remote-User,Remote-Email,Remote-Name,Remote-Groups,Remote-UserId"
      - "traefik.http.middlewares.authly-auth.forwardauth.authRequestHeaders=Cookie,X-Original-URL,X-Original-Method"

# Static configuration file (traefik.yml)
http:
  middlewares:
    authly-auth:
      forwardAuth:
        address: "http://authly-ip-address/api/authz/forward-auth"
        authResponseHeaders:
          - "X-Auth-User"
          - "X-Auth-Email"
          - "X-Auth-Name"
          - "X-Auth-UserId"
          - "X-Auth-Roles"
          - "X-Auth-Method"
          - "X-Auth-IsAdmin"
          - "X-Auth-HasTotp"
          - "Remote-User"
          - "Remote-Email"
          - "Remote-Name"
          - "Remote-Groups"
          - "Remote-UserId"
        authRequestHeaders:
          - "Cookie"
          - "X-Original-URL"
          - "X-Original-Method"
```

## 🐳 Portainer Integration with Authly SSO

This guide shows how to integrate Portainer with Authly for Single Sign-On (SSO) authentication using OAuth 2.0.

### Prerequisites

- Authly server running and accessible
- Portainer CE/EE instance
- Administrator access to both systems
- HTTPS configured for both services (recommended for production)

### Step 1: Configure OAuth Client in Authly

#### 1.1 Access Authly Admin Panel

1. Login to Authly as administrator
2. Click on **OAuth Clients** tab

#### 1.2 Create New OAuth Client

Click **"Add New Client"** and configure:

**Basic Information**
- **Client Type**: `Confidential`
- **Status**: `ENABLED`

**Client Credentials**
- **Client ID**: (auto-generated, e.g., `_43wapC7S1Pe-_B6uTNfCw`)
- **Client Secret**: (auto-generated, copy this value)

**Configuration**
- **Redirect URIs**: `https://portainer.example.com` (your Portainer URL)
- **Allowed Scopes**: 
  ```
  openid
  profile
  email
  ```
- **Allowed Grant Types**:
  ```
  AuthorizationCode
  RefreshToken
  ```

**Token Lifetimes**
- **Access Token Lifetime**: `3600 seconds` (1 hour)
- **Refresh Token Lifetime**: `86400 seconds` (24 hours)

**Security Settings**
- **Require PKCE**: `NO` (Portainer doesn't support PKCE)

#### 1.3 OAuth Endpoints Reference

After creating the client, note these endpoints for Portainer configuration:

```
Authorization URL: https://auth.example.com/oauth/authorize
Access Token URL: https://auth.example.com/oauth/token
Resource URL: https://auth.example.com/oauth/userinfo
Redirect URL: https://portainer.example.com (your Portainer URL)
Logout URL: https://auth.example.com/logout
```

### Step 2: Configure Portainer SSO

#### 2.1 Access Portainer Settings

1. Login to Portainer as administrator
2. Go to **Settings** → **Authentication**
3. Select **OAuth** authentication method

#### 2.2 OAuth Configuration

Fill in the OAuth configuration form with these values:

**OAuth Provider Settings**
- **Client ID**: `SovF_LgQkmTruv6EcOZbRA` (from Authly OAuth client)
- **Client Secret**: `xxxxxxxxxxxxxxxxxxxx` (from Authly OAuth client)
- **Authorization URL**: `https://auth.example.com/oauth/authorize`
- **Access Token URL**: `https://auth.example.com/oauth/token`
- **Resource URL**: `https://auth.example.com/oauth/userinfo`
- **Redirect URL**: `https://portainer.example.com`
- **Logout URL**: `https://auth.example.com/logout`

**User Mapping**
- **User identifier**: `email`
- **Scopes**: `email openid profile`

**Authentication Settings**
- **Auth Style**: `Auto Detect`

#### 2.3 SSO Settings

Enable these important settings:

- **Use SSO**: `true` ✅
- **Automatic user provisioning**: `true` ✅

#### 2.4 Save Configuration

Click **"Save settings"** to apply the OAuth configuration.

### Step 3: Test Integration

#### 3.1 Logout and Test

1. **Logout** from Portainer
2. Navigate to your Portainer URL
3. You should see **"Login with OAuth"** option
4. Click OAuth login button
5. You'll be redirected to Authly login page

#### 3.2 First Login Flow

1. **Login to Authly** with your credentials
2. **Grant permissions** if prompted
3. You'll be redirected back to Portainer
4. New user account will be **automatically created** in Portainer
5. You should be logged into Portainer dashboard

#### 3.3 Subsequent Logins

- Users with active Authly sessions will be automatically logged into Portainer
- No additional authentication required if session is valid

### Step 4: User Management

#### 4.1 Automatic User Provisioning

With **Automatic user provisioning = true**:

- New users are **automatically created** on first login
- User information is populated from Authly:
  - **Username**: From Authly preferred_username or email
  - **Email**: From Authly email claim
  - **Display Name**: From Authly name claim

#### 4.2 Role Assignment

**Default Role**: New users get default Portainer user role

**Admin Assignment**: 
- Portainer admins must be assigned manually in Portainer
- Or configure role mapping based on Authly groups (Portainer EE feature)

#### 4.3 User Synchronization

User information is updated on each login:
- Email address changes in Authly sync to Portainer
- Display name updates are reflected
- Account status (enabled/disabled) is respected

### Step 5: Advanced Configuration

#### 5.1 Custom Scopes (Optional)

You can request additional scopes in Portainer:

```
email openid profile read
```

Ensure these scopes are enabled in your Authly OAuth client.

#### 5.2 Role Mapping (Portainer EE)

For Portainer Business Edition, you can configure automatic role assignment:

1. In Authly, add users to groups or roles
2. Configure role mapping in Portainer OAuth settings
3. Users will automatically get assigned roles based on Authly groups

#### 5.3 Team Synchronization (Portainer EE)

Configure team membership based on Authly groups:

1. Create teams in Portainer
2. Map Authly groups to Portainer teams
3. Users will automatically join teams based on their Authly group membership

### Step 6: Troubleshooting

#### 6.1 Common Issues

**OAuth Redirect Mismatch**:
```bash
# Ensure redirect URLs match exactly
Authly OAuth Client: https://portainer.example.com
Portainer Redirect URL: https://portainer.example.com

# Fix: Update URLs to match
```

**Invalid Client Credentials**:
```bash
# Verify client ID and secret are correct
# Check Authly logs for authentication errors
docker-compose logs authly | grep -i oauth
```

**Scope Issues**:
```bash
# Ensure required scopes are enabled in Authly OAuth client
# Check Portainer logs for scope-related errors
```

#### 6.2 Debug Steps

1. **Check Authly Logs**:
   ```bash
   # Monitor OAuth flows
   docker-compose logs -f authly | grep -i oauth
   ```

2. **Verify OAuth Client**:
   - Login to Authly admin panel
   - Check OAuth Clients tab
   - Verify client is enabled and configured correctly

3. **Test OAuth Endpoints**:
   ```bash
   # Test authorization endpoint
   curl -I "https://auth.example.com/oauth/authorize?client_id=YOUR_CLIENT_ID&response_type=code"
   
   # Check discovery endpoint
   curl "https://auth.example.com/oauth/.well-known/oauth-authorization-server"
   ```

4. **Check Portainer Logs**:
   ```bash
   # Monitor Portainer OAuth integration
   docker logs portainer | grep -i oauth
   ```

#### 6.3 Network Issues

**HTTPS Requirements**:
- Both Authly and Portainer should use HTTPS in production
- Mixed HTTP/HTTPS can cause authentication issues

**Network Connectivity**:
- Ensure Portainer can reach Authly OAuth endpoints
- Check firewall rules and network policies

### Step 7: Security Considerations

#### 7.1 Production Setup

- **Use HTTPS** for both services
- **Secure client secret** storage
- **Regular secret rotation**
- **Monitor failed authentication attempts**

#### 7.2 Access Control

- **Review user permissions** regularly
- **Disable unused accounts** in Authly
- **Monitor OAuth token usage** in Authly admin panel

#### 7.3 Session Management

- **Configure appropriate token lifetimes**
- **Enable session timeout** in Portainer
- **Monitor active sessions** in both systems

### Summary

After completing this integration:

✅ **Single Sign-On**: Users login once to Authly, access Portainer seamlessly  
✅ **Automatic Provisioning**: New users are created automatically  
✅ **Centralized Authentication**: Manage all users in Authly  
✅ **Enhanced Security**: Leverage Authly's security features (2FA, lockouts, etc.)  
✅ **Audit Trail**: Track authentication events in Authly logs  

Your Portainer instance is now integrated with Authly for secure, centralized authentication!

## 📡 MQTT Integration

Authly supports MQTT integration for real-time event publishing and system monitoring. When enabled, authentication events and system status updates are published to configured MQTT topics.

### MQTT Configuration

Configure MQTT integration using environment variables or appsettings.json:

> **⚠️ Important**: WebSocket URI takes **priority** over TCP configuration. If `AUTHLY_MQTT_WEBSOCKET_URI` is set, the TCP settings (`Server`, `Port`, `UseTls`) are ignored. Configure **only one connection method**.

**Option 1: WebSocket Connection (Recommended for web integration)**
```bash
# Enable MQTT integration
AUTHLY_MQTT_ENABLED=true

# WebSocket connection (takes priority)
AUTHLY_MQTT_WEBSOCKET_URI=ws://mqtt.example.com:8083/mqtt

# Authentication and client settings
AUTHLY_MQTT_CLIENT_ID=authly-prod-001
AUTHLY_MQTT_USERNAME=authly_client
AUTHLY_MQTT_PASSWORD=secure_password
AUTHLY_MQTT_KEEP_ALIVE_SECONDS=60
```

**Option 2: TCP Connection (Traditional MQTT)**
```bash
# Enable MQTT integration
AUTHLY_MQTT_ENABLED=true

# Leave WebSocket URI empty for TCP connection
# AUTHLY_MQTT_WEBSOCKET_URI=  # Must be empty or not set

# TCP connection settings
AUTHLY_MQTT_SERVER=mqtt.example.com
AUTHLY_MQTT_PORT=1883
AUTHLY_MQTT_USE_TLS=false

# Authentication and client settings
AUTHLY_MQTT_CLIENT_ID=authly-prod-001
AUTHLY_MQTT_USERNAME=authly_client
AUTHLY_MQTT_PASSWORD=secure_password
AUTHLY_MQTT_KEEP_ALIVE_SECONDS=60
```

**Option 3: Secure TCP with TLS**
```bash
# Enable MQTT integration
AUTHLY_MQTT_ENABLED=true

# TCP with TLS encryption
AUTHLY_MQTT_SERVER=mqtt.example.com
AUTHLY_MQTT_PORT=8883
AUTHLY_MQTT_USE_TLS=true

# Authentication
AUTHLY_MQTT_CLIENT_ID=authly-secure-001
AUTHLY_MQTT_USERNAME=authly_client
AUTHLY_MQTT_PASSWORD=secure_password
```

### Event Payload Examples

**Login Success Event:**
```json
{
  "timestamp": "2025-07-29T10:30:00Z",
  "userId": "user123",
  "username": "john.doe",
  "email": "john@example.com"
}
```

**OAuth Success Event:**
```json
{
  "timestamp": "2025-07-29T10:30:00Z",
  "userId": "user123",
  "username": "john.doe",
  "email": "john@example.com"
}
```

**User Lockout Event:**
```json
{
  "timestamp": "2025-07-29T10:30:00Z",
  "userId": "user123",
  "username": "john.doe",
  "failedAttempts": 3,
  "lockoutDuration": 30
}
```

### MQTT Security

**TLS/SSL Configuration:**
```bash
# Enable TLS encryption
AUTHLY_MQTT_USE_TLS=true
AUTHLY_MQTT_PORT=8883

# For self-signed certificates, additional configuration may be needed
```

**Authentication:**
```bash
# Username/password authentication
AUTHLY_MQTT_USERNAME=authly_service
AUTHLY_MQTT_PASSWORD=strong_secure_password

# Client certificate authentication (advanced)
# Requires additional configuration in appsettings.json
```

### MQTT Broker Compatibility

Authly's MQTT client is compatible with:

- **Eclipse Mosquitto** - Open source MQTT broker
- **HiveMQ** - Enterprise MQTT platform
- **AWS IoT Core** - Amazon's managed MQTT service  
- **Azure IoT Hub** - Microsoft's IoT platform
- **Google Cloud IoT Core** - Google's IoT service
- **EMQX** - Scalable MQTT broker
- **VerneMQ** - High-performance MQTT broker

## 🔐 OAuth 2.0 Authorization Server

Authly includes a built-in OAuth 2.0 Authorization Server for third-party application integration, following RFC 6749 and OAuth 2.0 Security Best Practices.

### OAuth 2.0 Endpoints

| Endpoint | Method | Description | Standards |
|----------|--------|-------------|-----------|
| `/oauth/authorize` | GET | Authorization endpoint | RFC 6749 Section 4.1.1 |
| `/oauth/token` | POST | Token endpoint | RFC 6749 Section 4.1.3 |
| `/oauth/userinfo` | GET/POST | UserInfo endpoint | OpenID Connect Core |
| `/oauth/revoke` | POST | Token revocation | RFC 7009 |
| `/oauth/consent` | GET/POST | Consent management | Custom |
| `/oauth/.well-known/oauth-authorization-server` | GET | Discovery metadata | RFC 8414 |

### Authorization Endpoint - `/oauth/authorize`

**Request Parameters:**

```http
GET /oauth/authorize?
  response_type=code&
  client_id=your_client_id&
  redirect_uri=https://yourapp.com/callback&
  scope=openid profile email&
  state=random_state_value&
  code_challenge=challenge&
  code_challenge_method=S256
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` for authorization code flow |
| `client_id` | Yes | Client identifier |
| `redirect_uri` | Yes | Callback URL (must be pre-registered) |
| `scope` | No | Space-separated scopes (default: `openid`) |
| `state` | Recommended | CSRF protection token |
| `code_challenge` | PKCE | Base64URL-encoded SHA256 hash of code_verifier |
| `code_challenge_method` | PKCE | `S256` or `plain` (S256 recommended) |
| `nonce` | OpenID | Replay attack protection |

**Example Success Response:**

```http
HTTP/1.1 302 Found
Location: https://yourapp.com/callback?code=abc123&state=xyz
```

**Example Error Response:**

```http
HTTP/1.1 302 Found
Location: https://yourapp.com/callback?error=invalid_scope&error_description=Unknown+scope&state=xyz
```

### Token Endpoint - `/oauth/token`

**Authorization Code Exchange:**

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=abc123&
redirect_uri=https://yourapp.com/callback&
client_id=your_client_id&
client_secret=your_client_secret&
code_verifier=verifier_string
```

**Refresh Token:**

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=refresh_token_value&
client_id=your_client_id&
client_secret=your_client_secret&
scope=openid profile
```

**Success Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_value",
  "scope": "openid profile email"
}
```

### UserInfo Endpoint - `/oauth/userinfo`

**Request:**

```http
GET /oauth/userinfo
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Success Response (200 OK):**

```json
{
  "sub": "user123",
  "name": "John Doe",
  "preferred_username": "johndoe",
  "email": "john@example.com",
  "email_verified": true
}
```

**Claims by Scope:**

| Scope | Claims Included |
|-------|----------------|
| `openid` | `sub` |
| `profile` | `name`, `preferred_username` |
| `email` | `email`, `email_verified` |

### Token Revocation - `/oauth/revoke`

**Request:**

```http
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=access_token_or_refresh_token&
token_type_hint=access_token&
client_id=your_client_id&
client_secret=your_client_secret
```

**Response:**
- `200 OK` - Always returned per RFC 7009 (even if token not found)

### Discovery Endpoint - `/oauth/.well-known/oauth-authorization-server`

**Response (200 OK):**

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "userinfo_endpoint": "https://auth.example.com/oauth/userinfo",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "scopes_supported": ["openid", "profile", "email", "read", "write"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"]
}
```

### Security Features

**PKCE (Proof Key for Code Exchange):**
- Supports both `S256` and `plain` methods
- Can be required per client configuration
- Protects against authorization code interception

**Client Authentication:**
- `client_secret_post` - Client credentials in POST body
- `client_secret_basic` - Client credentials in Authorization header

**Token Security:**
- JWT access tokens with HMAC SHA-256 signing
- Configurable token lifetimes per client
- Automatic token cleanup and expiration
- Token revocation support

**Available Scopes:**
- `openid` - Required for OpenID Connect
- `profile` - Access to user profile information
- `email` - Access to user email address
- `read` - Read access to user data
- `write` - Write access to user data (privileged)

### OAuth Client Management

OAuth clients are managed through the admin panel at `/admin` → OAuth Clients tab:

**Client Configuration:**
- **Client ID & Secret** - Generated automatically
- **Redirect URIs** - Whitelist of valid callback URLs
- **Allowed Scopes** - Permitted scopes for the client
- **Grant Types** - Supported OAuth flows
- **Token Lifetimes** - Access and refresh token expiration
- **PKCE Settings** - PKCE requirements and methods

### Integration Example

**Authorization Code Flow with PKCE:**

```javascript
// 1. Generate PKCE values
const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// 2. Redirect to authorization endpoint
const authUrl = new URL('https://auth.example.com/oauth/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your_client_id');
authUrl.searchParams.set('redirect_uri', 'https://yourapp.com/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', generateState());
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();

// 3. Handle callback and exchange code for tokens
const response = await fetch('https://auth.example.com/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: 'https://yourapp.com/callback',
    client_id: 'your_client_id',
    client_secret: 'your_client_secret',
    code_verifier: codeVerifier
  })
});

const tokens = await response.json();

// 4. Use access token to get user info
const userInfo = await fetch('https://auth.example.com/oauth/userinfo', {
  headers: {
    'Authorization': `Bearer ${tokens.access_token}`
  }
});

const user = await userInfo.json();
console.log(user); // { sub: "123", name: "John Doe", email: "john@example.com" }
```

### Error Handling

**Authorization Errors:**
- `invalid_request` - Missing or invalid parameters
- `unauthorized_client` - Client not authorized for this grant type
- `access_denied` - User denied authorization
- `unsupported_response_type` - Invalid response type
- `invalid_scope` - Invalid or unknown scope
- `server_error` - Internal server error

**Token Errors:**
- `invalid_request` - Missing or invalid parameters
- `invalid_client` - Invalid client credentials
- `invalid_grant` - Invalid authorization code or refresh token
- `unauthorized_client` - Client not authorized for this grant type
- `unsupported_grant_type` - Unsupported grant type
- `invalid_scope` - Invalid scope parameter

## 🚀 Google OAuth Setup

### Google Cloud Console Configuration

1. **Create Google Cloud Project**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one

2. **Enable OAuth2 API**
   - Go to APIs & Services → Library
   - Enable "Google+ API" or "Google Identity"

3. **Create OAuth 2.0 Credentials**
   - Go to APIs & Services → Credentials
   - Click "Create Credentials" → "OAuth 2.0 Client IDs"
   - Select "Web application"

4. **Configure Redirect URIs**

```bash
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

```bash
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

```bash
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

```bash
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

```bash
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

```bash
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
- **Authy** compatible
- **Any RFC 6238 compliant** authenticator app

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
├── users.json                  # User accounts and profiles
├── ip-bans.json                # IP ban records and timestamps
├── oauth-access-tokens.json    # OAuth access tokens
├── oauth-refresh-tokens.json   # OAuth refresh tokens
├── oauth-clients.json          # OAuth clients
└── oauth-auth-codes.json       # OAuth auth codes
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

# Build Docker image (optional - pre-built image available)
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
| `X-Auth-UserId` | User ID | `11asdfs-as6d5f4-asdf654` |
| `X-Auth-Method` | Auth method | `session` |
| `X-Auth-IsAdmin` | Administrator flag | `true` |
| `X-Auth-HasTotp` | TOTP enabled flag | `true` |
| `Remote-User` | Username | `john.doe` |
| `Remote-Email` | Email address | `john@example.com` |
| `Remote-Name` | Display name | `John Doe` |
| `Remote-Groups` | User roles (comma-separated) | `admin,user` |
| `Remote-UserId` | User ID | `11asdfs-as6d5f4-asdf654` |

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

#### Image Issues

```bash
# Ensure you can pull the image
docker pull ghcr.io/mklouda4/authly:latest

# Check for registry authentication if needed
docker login ghcr.io

# Verify image exists
docker image ls | grep authly
```

#### Admin Panel Access Issues

```bash
# Verify admin user exists and has admin privileges
docker-compose logs authly | grep -i "admin"

# Check user data
cat ./data/users.json | jq '.[] | select(.Administrator == true)'

# Reset admin user if needed
docker-compose exec authly /bin/bash
# Then use admin panel or recreate admin user
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

# Test admin panel access
curl -I http://localhost:8080/admin

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

### Admin Panel Debugging

```bash
# Check admin panel accessibility
curl -I http://localhost:8080/admin

# Monitor admin actions
docker-compose logs -f authly | grep -i "admin"

# Check for admin-related errors
docker-compose logs authly | grep -E "(ERROR|WARN)" | grep -i "admin"

# Verify user permissions
curl -b "cookies.txt" http://localhost:8080/auth/user
```

## 🤝 Support

### Getting Help

1. **Check the logs** first: `docker-compose logs authly`
2. **Review configuration** in `.env` file
3. **Test health endpoints** to verify service status
4. **Access admin panel** to monitor system status
5. **Check GitHub Issues** for known problems

### Reporting Issues

When reporting issues, please include:
- Docker Compose logs
- Configuration (without sensitive data)
- Steps to reproduce
- Expected vs actual behavior
- OAuth-specific details if applicable
- Admin panel screenshots if relevant

### Configuration Checklist

Before deploying to production:

- [ ] Change default admin credentials
- [ ] Configure proper domain and base URL
- [ ] Set up OAuth providers with production URLs
- [ ] Enable HTTPS with valid certificates
- [ ] Configure firewall rules
- [ ] Set up monitoring and health checks
- [ ] Review security settings (lockout, rate limiting)
- [ ] Test SSO integration with your applications
- [ ] Backup data directory
- [ ] Review logs for any warnings or errors

### Performance Tuning

For high-traffic environments:

```bash
# Increase container resources
docker-compose up --scale authly=3

# Use Redis for session storage (requires custom configuration)
# Configure load balancer with sticky sessions
# Monitor metrics and adjust rate limits accordingly
# Consider using external database for user storage
```

### Security Hardening

Additional security recommendations:

- Use strong, unique passwords for OAuth applications
- Regularly rotate OAuth client secrets
- Monitor failed authentication attempts
- Set up alerts for suspicious activity
- Keep the application updated
- Use HTTPS everywhere
- Implement proper firewall rules
- Regular security audits

---

**License**: MIT  
**Author**: Built with ❤️ for secure authentication

**Version**: 1.0.0  
**ASP.NET Core**: 8.0  
**Docker Image**: ghcr.io/mklouda4/authly:latest
