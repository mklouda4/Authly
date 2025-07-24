# Authly Docker Deployment Guide

This guide covers various deployment options for Authly using Docker, from simple standalone containers to production-ready orchestration setups.

## 🐳 Deployment Options

### 1. Docker Standalone

For simple single-container deployments:

```bash
# Build image
docker build -t authly:latest .

# Run container with environment variables
docker run -d \
  --name authly-app \
  -p 8080:80 \
  -p 9090:9090 \
  -v authly_data:/app/wwwroot/data \
  -v authly_keys:/app/wwwroot/keys \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e ASPNETCORE_URLS=http://+:80 \
  -e ASPNETCORE_FORWARDEDHEADERS_ENABLED=true \
  -e AUTHLY_NAME="My Company Auth" \
  -e AUTHLY_DOMAIN=your-domain.com \
  -e AUTHLY_BASE_URL=https://auth.your-domain.com \
  -e AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3 \
  -e AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5 \
  -e AUTHLY_ENABLE_METRICS=true \
  -e AUTHLY_ENABLE_GOOGLE=true \
  -e GOOGLE_CLIENT_ID=your-google-client-id \
  -e GOOGLE_CLIENT_SECRET=your-google-secret \
  --restart unless-stopped \
  authly:latest
```

### 2. Docker Compose (Recommended)

Complete setup with health monitoring:

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  authly:
    image: authly:latest
    container_name: authly-app
    ports:
      - "${HTTP_PORT:-8080}:80"
      - "${METRICS_PORT:-9090}:9090"
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:80
      - ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
      - ASPNETCORE_HTTPS_PORT=443
      
      # Application Settings
      - AUTHLY_ALLOW_REGISTRATION=${AUTHLY_ALLOW_REGISTRATION:-false}
      - AUTHLY_NAME=${AUTHLY_NAME:-Authly}
      - AUTHLY_DOMAIN=${AUTHLY_DOMAIN}
      - AUTHLY_BASE_URL=${AUTHLY_BASE_URL}
      - AUTHLY_VERSION=${AUTHLY_VERSION:-1.0.0}
      - AUTHLY_DEBUG_LOGGING=${AUTHLY_DEBUG_LOGGING:-false}
      - AUTHLY_ENABLE_METRICS=${AUTHLY_ENABLE_METRICS:-true}
      
      # External OAuth Configuration
      - AUTHLY_ENABLE_GOOGLE=${AUTHLY_ENABLE_GOOGLE:-false}
      - AUTHLY_ENABLE_MICROSOFT=${AUTHLY_ENABLE_MICROSOFT:-false}
      - AUTHLY_ENABLE_GITHUB=${AUTHLY_ENABLE_GITHUB:-false}
      - AUTHLY_ENABLE_FACEBOOK=${AUTHLY_ENABLE_FACEBOOK:-false}
      
      # Google OAuth
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID:-}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET:-}
      
      # Microsoft OAuth
      - MICROSOFT_CLIENT_ID=${MICROSOFT_CLIENT_ID:-}
      - MICROSOFT_CLIENT_SECRET=${MICROSOFT_CLIENT_SECRET:-}
      - MICROSOFT_TENANT_ID=${MICROSOFT_TENANT_ID:-common}
      
      # GitHub OAuth
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID:-}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET:-}
      
      # Facebook OAuth
      - FACEBOOK_APP_ID=${FACEBOOK_APP_ID:-}
      - FACEBOOK_APP_SECRET=${FACEBOOK_APP_SECRET:-}
      
      # Security Configuration
      - AUTHLY_USER_LOCKOUT_ENABLED=${AUTHLY_USER_LOCKOUT_ENABLED:-true}
      - AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=${AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS:-3}
      - AUTHLY_USER_LOCKOUT_DURATION=${AUTHLY_USER_LOCKOUT_DURATION:-30}
      - AUTHLY_USER_LOCKOUT_SLIDING_WINDOW=${AUTHLY_USER_LOCKOUT_SLIDING_WINDOW:-true}
      - AUTHLY_USER_LOCKOUT_WINDOW=${AUTHLY_USER_LOCKOUT_WINDOW:-15}
      
      # IP Rate Limiting
      - AUTHLY_IP_RATE_LIMIT_ENABLED=${AUTHLY_IP_RATE_LIMIT_ENABLED:-true}
      - AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=${AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS:-5}
      - AUTHLY_IP_RATE_LIMIT_BAN_DURATION=${AUTHLY_IP_RATE_LIMIT_BAN_DURATION:-60}
      - AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW=${AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW:-false}
      - AUTHLY_IP_RATE_LIMIT_WINDOW=${AUTHLY_IP_RATE_LIMIT_WINDOW:-30}
      
    volumes:
      - authly_data:/app/wwwroot/data
      - authly_keys:/app/wwwroot/keys
      
    networks:
      - authly-network
    restart: unless-stopped

  healthcheck-ui:
    image: xabarilcoding/healthchecksui:latest
    container_name: authly-healthcheck-ui
    ports:
      - "${HEALTHCHECK_UI_PORT:-8090}:80"
    environment:
      - HealthChecksUI__HealthChecks__0__Name=Authly Application
      - HealthChecksUI__HealthChecks__0__Uri=http://authly:80/health
      - HealthChecksUI__HealthChecks__1__Name=Authly Readiness
      - HealthChecksUI__HealthChecks__1__Uri=http://authly:80/health/ready
      - HealthChecksUI__HealthChecks__2__Name=Authly Liveness
      - HealthChecksUI__HealthChecks__2__Uri=http://authly:80/health/live
    depends_on:
      - authly
    networks:
      - authly-network
    restart: unless-stopped

volumes:
  authly_data:
    driver: local
  authly_keys:
    driver: local

networks:
  authly-network:
    driver: bridge
```

**Deployment commands:**
```bash
# Start application with health check UI
docker-compose up -d

# View logs
docker-compose logs -f

# Stop application
docker-compose down

# Update and restart
docker-compose pull && docker-compose up -d
```

### 3. Portainer Stack

Perfect for Portainer-managed environments. Use this stack configuration in Portainer:

**Stack Configuration:**
```yaml
version: '3.8'
services:
  authly:
    image: authly:latest
    container_name: authly-app
    ports:
      - "${HTTP_PORT:-8088}:80"
      - "${METRICS_PORT:-9099}:9090"
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:80
      - ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
      - ASPNETCORE_HTTPS_PORT=443
      
      # Application Settings
      - AUTHLY_ALLOW_REGISTRATION=false
      - AUTHLY_NAME=${AUTHLY_NAME:-Authly}
      - AUTHLY_DOMAIN=${AUTHLY_DOMAIN}
      - AUTHLY_BASE_URL=${AUTHLY_BASE_URL:-localhost:80}
      - AUTHLY_VERSION=${AUTHLY_VERSION:-1.0.0}
      - AUTHLY_DEBUG_LOGGING=${AUTHLY_DEBUG_LOGGING:-false}
      - AUTHLY_ENABLE_METRICS=${AUTHLY_ENABLE_METRICS:-true}
      
      # External OAuth Configuration
      - AUTHLY_ENABLE_GOOGLE=${AUTHLY_ENABLE_GOOGLE:-false}
      - AUTHLY_ENABLE_MICROSOFT=${AUTHLY_ENABLE_MICROSOFT:-false}
      - AUTHLY_ENABLE_GITHUB=${AUTHLY_ENABLE_GITHUB:-false}
      - AUTHLY_ENABLE_FACEBOOK=${AUTHLY_ENABLE_FACEBOOK:-false}
      
      # Google OAuth
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID:-}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET:-}
      
      # Microsoft OAuth
      - MICROSOFT_CLIENT_ID=${MICROSOFT_CLIENT_ID:-}
      - MICROSOFT_CLIENT_SECRET=${MICROSOFT_CLIENT_SECRET:-}
      - MICROSOFT_TENANT_ID=${MICROSOFT_TENANT_ID:-common}
      
      # GitHub OAuth
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID:-}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET:-}
      
      # Facebook OAuth
      - FACEBOOK_APP_ID=${FACEBOOK_APP_ID:-}
      - FACEBOOK_APP_SECRET=${FACEBOOK_APP_SECRET:-}
      
      # User Lockout Security Configuration
      - AUTHLY_USER_LOCKOUT_ENABLED=${AUTHLY_USER_LOCKOUT_ENABLED:-true}
      - AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=${AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS:-3}
      - AUTHLY_USER_LOCKOUT_DURATION=${AUTHLY_USER_LOCKOUT_DURATION:-30}
      - AUTHLY_USER_LOCKOUT_SLIDING_WINDOW=${AUTHLY_USER_LOCKOUT_SLIDING_WINDOW:-true}
      - AUTHLY_USER_LOCKOUT_WINDOW=${AUTHLY_USER_LOCKOUT_WINDOW:-15}
      
      # IP Rate Limiting Configuration
      - AUTHLY_IP_RATE_LIMIT_ENABLED=${AUTHLY_IP_RATE_LIMIT_ENABLED:-true}
      - AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=${AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS:-5}
      - AUTHLY_IP_RATE_LIMIT_BAN_DURATION=${AUTHLY_IP_RATE_LIMIT_BAN_DURATION:-60}
      - AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW=${AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW:-false}
      - AUTHLY_IP_RATE_LIMIT_WINDOW=${AUTHLY_IP_RATE_LIMIT_WINDOW:-30}
      
    volumes:
      - authly_data:/app/wwwroot/data
      - authly_keys:/app/wwwroot/keys
      
    networks:
      - authly-network
    restart: unless-stopped

  healthcheck-ui:
    image: xabarilcoding/healthchecksui:latest
    container_name: authly-healthcheck-ui
    ports:
      - "${HEALTHCHECK_UI_PORT:-8090}:80"
    environment:
      - HealthChecksUI__HealthChecks__0__Name=Authly Application
      - HealthChecksUI__HealthChecks__0__Uri=http://authly:80/health
      - HealthChecksUI__HealthChecks__1__Name=Authly Readiness
      - HealthChecksUI__HealthChecks__1__Uri=http://authly:80/health/ready
      - HealthChecksUI__HealthChecks__2__Name=Authly Liveness
      - HealthChecksUI__HealthChecks__2__Uri=http://authly:80/health/live
    depends_on:
      - authly
    networks:
      - authly-network
    restart: unless-stopped

volumes:
  authly_data:
    driver: local
  authly_keys:
    driver: local

networks:
  authly-network:
    driver: bridge
```

### 4. Environment Variables (.env file)

Create a `.env` file with your configuration:

```bash
# Application Settings
AUTHLY_NAME=Authly
AUTHLY_DOMAIN=mjhome.cz
AUTHLY_BASE_URL=https://auth.mjhome.cz
AUTHLY_VERSION=1.0.0
AUTHLY_DEBUG_LOGGING=false
AUTHLY_ENABLE_METRICS=true

# Security Settings
AUTHLY_USER_LOCKOUT_ENABLED=true
AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3
AUTHLY_USER_LOCKOUT_DURATION=30
AUTHLY_USER_LOCKOUT_SLIDING_WINDOW=true
AUTHLY_USER_LOCKOUT_WINDOW=15

AUTHLY_IP_RATE_LIMIT_ENABLED=true
AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5
AUTHLY_IP_RATE_LIMIT_BAN_DURATION=60
AUTHLY_IP_RATE_LIMIT_SLIDING_WINDOW=false
AUTHLY_IP_RATE_LIMIT_WINDOW=30

# Port Configuration
HTTP_PORT=8088
HTTPS_PORT=8443
METRICS_PORT=9099
HEALTHCHECK_UI_PORT=8090

# OAuth Providers
AUTHLY_ENABLE_GOOGLE=true
AUTHLY_ENABLE_MICROSOFT=false
AUTHLY_ENABLE_GITHUB=true
AUTHLY_ENABLE_FACEBOOK=false

# Google OAuth Credentials
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
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
```

## 🔗 Single Sign-On (SSO) Configuration

Authly supports Single Sign-On integration with reverse proxies like nginx, Caddy, and Traefik through the `auth_request` pattern.

### SSO Endpoints

| Endpoint | Method | Description | Response |
|----------|--------|-------------|----------|
| `/auth` | GET | Authentication verification | `200` (OK) / `401` (Unauthorized) / `403` (Forbidden) |
| `/auth/user` | GET | User information | JSON with user details |
| `/auth/login` | GET | Login redirect | Redirects to login page |

### OAuth Login Endpoints

| Provider | Login Endpoint | Callback Endpoint |
|----------|----------------|-------------------|
| Google | `/google-login` | `/google/oauth2/callback` |
| Microsoft | `/microsoft-login` | `/microsoft/oauth2/callback` |
| GitHub | `/github-login` | `/github/oauth2/callback` |
| Facebook | `/facebook-login` | `/facebook/oauth2/callback` |

### Response Headers

When successfully authenticated, Authly provides these headers:

| Header | Description | Example |
|--------|-------------|---------|
| `X-Auth-User` | Username | `john.doe` |
| `X-Auth-Email` | Email address | `john@example.com` |
| `X-Auth-Name` | Display name | `John Doe` |
| `X-Auth-UserId` | User ID | `user-123` |
| `X-Auth-Roles` | User roles (comma-separated) | `admin,user` |
| `X-Auth-Authenticated` | Authentication status | `true` |
| `X-Auth-External` | External OAuth flag | `true` |

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
    image: authly:latest
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

## 🛠️ Application Integration

### Headers Available in Your Applications

Based on the actual Authly API response headers:

```
# X-Auth-* headers (primary)
X-Auth-User: john.doe
X-Auth-Email: john.doe@company.com
X-Auth-Name: John Doe
X-Auth-UserId: user-123
X-Auth-Roles: user,admin,Administrator
X-Auth-Method: token
X-Auth-IsAdmin: true
X-Auth-HasTotp: false

# Remote-* headers (compatibility)
Remote-User: john.doe
Remote-Email: john.doe@company.com
Remote-Name: John Doe
Remote-UserId: user-123
Remote-Groups: user,admin,Administrator
```

### Integration Examples

#### Node.js/Express

```javascript
app.use((req, res, next) => {
  req.user = {
    username: req.headers['x-auth-user'] || req.headers['remote-user'],
    email: req.headers['x-auth-email'] || req.headers['remote-email'],
    name: req.headers['x-auth-name'] || req.headers['remote-name'],
    userId: req.headers['x-auth-userid'] || req.headers['remote-userid'],
    roles: (req.headers['x-auth-roles'] || req.headers['remote-groups'] || '').split(',').filter(r => r),
    method: req.headers['x-auth-method'] || 'unknown',
    isAdmin: req.headers['x-auth-isadmin'] === 'true',
    hasTotp: req.headers['x-auth-hastotp'] === 'true'
  };
  next();
});

// Check if user has specific role
function hasRole(req, role) {
  return req.user?.roles?.includes(role) || false;
}

// Check if user is admin (multiple ways)
function isAdmin(req) {
  return req.user?.isAdmin || 
         hasRole(req, 'admin') || 
         hasRole(req, 'Administrator');
}

// Check authentication method
function isTokenAuth(req) {
  return req.user?.method === 'token';
}
```

#### Python/Flask

```python
from flask import request, g

@app.before_request
def load_user():
    g.user = {
        'username': request.headers.get('X-Auth-User') or request.headers.get('Remote-User'),
        'email': request.headers.get('X-Auth-Email') or request.headers.get('Remote-Email'),
        'name': request.headers.get('X-Auth-Name') or request.headers.get('Remote-Name'),
        'user_id': request.headers.get('X-Auth-UserId') or request.headers.get('Remote-UserId'),
        'roles': (request.headers.get('X-Auth-Roles') or request.headers.get('Remote-Groups') or '').split(','),
        'method': request.headers.get('X-Auth-Method', 'unknown'),
        'is_admin': request.headers.get('X-Auth-IsAdmin') == 'true',
        'has_totp': request.headers.get('X-Auth-HasTotp') == 'true'
    }

def has_role(role):
    return role in (g.user.get('roles') or [])

def is_admin():
    return g.user.get('is_admin') or has_role('admin') or has_role('Administrator')

def is_token_auth():
    return g.user.get('method') == 'token'
```

#### ASP.NET Core

```csharp
app.Use(async (context, next) =>
{
    var user = new
    {
        Username = context.Request.Headers["X-Auth-User"].FirstOrDefault() ?? 
                  context.Request.Headers["Remote-User"].FirstOrDefault(),
        Email = context.Request.Headers["X-Auth-Email"].FirstOrDefault() ?? 
               context.Request.Headers["Remote-Email"].FirstOrDefault(),
        Name = context.Request.Headers["X-Auth-Name"].FirstOrDefault() ?? 
              context.Request.Headers["Remote-Name"].FirstOrDefault(),
        UserId = context.Request.Headers["X-Auth-UserId"].FirstOrDefault() ?? 
                context.Request.Headers["Remote-UserId"].FirstOrDefault(),
        Roles = (context.Request.Headers["X-Auth-Roles"].FirstOrDefault() ?? 
                context.Request.Headers["Remote-Groups"].FirstOrDefault() ?? "")
                .Split(',', StringSplitOptions.RemoveEmptyEntries),
        Method = context.Request.Headers["X-Auth-Method"].FirstOrDefault() ?? "unknown",
        IsAdmin = context.Request.Headers["X-Auth-IsAdmin"].FirstOrDefault() == "true",
        HasTotp = context.Request.Headers["X-Auth-HasTotp"].FirstOrDefault() == "true"
    };
    
    context.Items["User"] = user;
    await next();
});

// Extension methods for role checking
public static bool HasRole(this HttpContext context, string role)
{
    if (context.Items["User"] is not dynamic user) return false;
    return ((string[])user.Roles).Contains(role);
}

public static bool IsAdmin(this HttpContext context)
{
    if (context.Items["User"] is not dynamic user) return false;
    return user.IsAdmin || context.HasRole("admin") || context.HasRole("Administrator");
}

public static bool IsTokenAuth(this HttpContext context)
{
    if (context.Items["User"] is not dynamic user) return false;
    return user.Method == "token";
}
```

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

## 🚨 Troubleshooting

### Authentication Status Check

```bash
# Test authentication endpoint directly
curl -I -b "cookies.txt" http://localhost:8080/auth

# Get user information
curl -b "cookies.txt" http://localhost:8080/auth/user

# Test OAuth endpoints
curl -I "http://localhost:8080/google-login"
curl -I "http://localhost:8080/microsoft-login"
curl -I "http://localhost:8080/github-login"
```

### Common Issues

#### Port Conflicts

```bash
# Check if ports are in use
netstat -tulpn | grep :8080
netstat -tulpn | grep :8090

# Use different ports in .env
HTTP_PORT=8081
METRICS_PORT=9091
```

#### OAuth Configuration Issues

```bash
# Verify OAuth configuration
docker logs authly-app | grep -E "(OAuth|Login|Error)"

# Check environment variables
docker exec authly-app env | grep -E "(GOOGLE|MICROSOFT|GITHUB|FACEBOOK)"
```

#### Data Permission Issues

```bash
# Check volume mounts
docker inspect authly-app | grep -A 10 "Mounts"

# Check container data directory
docker exec authly-app ls -la /app/wwwroot/data
```

### Debug Commands

```bash
# Container status
docker ps -a

# View detailed logs
docker logs -f authly-app

# Execute commands in container
docker exec -it authly-app /bin/bash

# Test endpoints
curl -I http://localhost:8080/health
curl http://localhost:8080/auth/user
```

### OAuth Provider Testing

```bash
# Test Google OAuth flow
curl -I "http://localhost:8080/google-login?returnUrl=/dashboard"

# Test GitHub OAuth flow
curl -I "http://localhost:8080/github-login?returnUrl=/dashboard"

# Monitor OAuth logs
docker logs -f authly-app | grep -E "(Google|GitHub|OAuth)"
```

## 🔒 Security Considerations

### Production Deployment Checklist

- [ ] Change default admin credentials immediately
- [ ] Use HTTPS with valid SSL certificates
- [ ] Configure proper domain and base URL
- [ ] Set up OAuth providers with production redirect URIs
- [ ] Enable firewall rules to restrict access
- [ ] Set up monitoring and alerting
- [ ] Review security settings (lockout, rate limiting)
- [ ] Backup data and keys volumes regularly
- [ ] Use secrets management for sensitive variables
- [ ] Monitor logs for security events

### Network Security

```bash
# Restrict admin panel access (example with nginx)
location /admin {
    allow 192.168.1.0/24;  # Internal network only
    deny all;
    auth_request /auth;
    proxy_pass http://authly:8080;
}

# Use Docker networks for isolation
docker network create --driver bridge authly-secure
```

### Secrets Management

For production environments, consider using Docker secrets or external secret management:

```bash
# Using Docker secrets
echo "your-google-secret" | docker secret create google_client_secret -
echo "your-github-secret" | docker secret create github_client_secret -

# Reference in docker-compose.yml
secrets:
  - google_client_secret
  - github_client_secret
```

---

**Deployment Guide Version**: 1.0.0  
**Compatible with Authly**: 1.0.0+  
**Docker**: Required  
**Platforms**: Linux, Windows, macOS