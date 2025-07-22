# Authly Docker Deployment

## Deployment

### 1. Docker Only
```bash
# Build image
docker build -t authly:latest .

# Run container with environment variables
docker run -d \
  --name authly-app \
  -p 8080:80 \
  -v $(pwd)/data:/app/data \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e AUTHLY_NAME=MyAuthly \
  -e AUTHLY_DOMAIN=you-domain.com \
  -e AUTHLY_BASE_URL=https://auth.your-domain.com \
  -e AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3 \
  -e AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5 \
  -e AUTHLY_ENABLE_METRICS=true \
  -e AUTHLY_ENABLE_GOOGLE=true \
  -e AUTHLY_ENABLE_MICROSOFT=true \
  -e AUTHLY_ENABLE_GITHUB=true \
  -e AUTHLY_ENABLE_FACEBOOK=true \
  -e GOOGLE_CLIENT_ID=your-google-client-id \
  -e GOOGLE_CLIENT_SECRET=your-google-secret \
  -e MICROSOFT_CLIENT_ID=your-microsoft-client-id \
  -e MICROSOFT_CLIENT_SECRET=your-microsoft-secret \
  -e MICROSOFT_TENANT_ID=common \
  -e GITHUB_CLIENT_ID=your-github-client-id \
  -e GITHUB_CLIENT_SECRET=your-github-secret \
  -e FACEBOOK_APP_ID=your-facebook-app-id \
  -e FACEBOOK_APP_SECRET=your-facebook-app-secret \
  authly:latest
```

### 2. Docker Compose (Recommended)
```bash
# Start application with health check UI
docker-compose up -d

# View logs
docker-compose logs -f

# Stop application
docker-compose down
```

### 3. Custom .env File
```bash
# Copy template
cp .env.example .env

# Edit values as needed
nano .env

# Start application
docker-compose up -d
```

#### Example .env Configuration
```env
# Application Settings
AUTHLY_NAME=My Company Auth
AUTHLY_DOMAIN=your-domain.com
AUTHLY_BASE_URL=https://auth.your-domain.com
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

# Security Configuration
AUTHLY_USER_LOCKOUT_ENABLED=true
AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3
AUTHLY_USER_LOCKOUT_DURATION=30
AUTHLY_IP_RATE_LIMIT_ENABLED=true
AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5
AUTHLY_IP_RATE_LIMIT_BAN_DURATION=60

# Ports
HTTP_PORT=8080
HTTPS_PORT=8443
METRICS_PORT=9090
```

## Single Sign-On (SSO) Configuration

Authly supports Single Sign-On integration with reverse proxies like nginx and Caddy through the `auth_request` pattern.

### SSO Endpoints

Authly provides the following endpoints for external authentication:

- **`/auth`** - Authentication verification endpoint (returns 200 if authenticated, 401/403 if not)
- **`/auth/user`** - User information endpoint (returns JSON with user details)
- **`/auth/login`** - Login redirect endpoint (redirects to login page with return URL)

### OAuth Login Endpoints

| Provider | Login Endpoint | Callback Endpoint |
|----------|----------------|-------------------|
| Google | `/google-login` | `/google/oauth2/callback` |
| Microsoft | `/microsoft-login` | `/microsoft/oauth2/callback` |
| GitHub | `/github-login` | `/github/oauth2/callback` |
| Facebook | `/facebook-login` | `/facebook/oauth2/callback` |

### Response Headers

The `/auth` endpoint sets the following headers for authenticated users:

- `X-Auth-User` - Username
- `X-Auth-Email` - User email
- `X-Auth-Name` - Display name
- `X-Auth-UserId` - User ID
- `X-Auth-Roles` - Comma-separated list of roles
- `X-Auth-Authenticated` - Authentication status (`true`)
- `X-Auth-External` - External authentication flag (`true` for OAuth users)

### nginx Configuration Example
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
        auth_request_set $authenticated $upstream_http_x_auth_authenticated;
        auth_request_set $external $upstream_http_x_auth_external;
        
        proxy_pass http://your-app:3000;
        proxy_set_header X-Auth-User $user;
        proxy_set_header X-Auth-Email $email;
        proxy_set_header X-Auth-Name $name;
        proxy_set_header X-Auth-Roles $roles;
        proxy_set_header X-Auth-Authenticated $authenticated;
        proxy_set_header X-Auth-External $external;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
    }

    # Redirect to login on authentication failure
    error_page 401 = @error401;
    location @error401 {
        return 302 http://authly:8080/auth/login?returnUrl=$scheme://$http_host$request_uri;
    }
    
    # Handle forbidden access
    error_page 403 = @error403;
    location @error403 {
        return 302 http://authly:8080/login?error=access_denied&returnUrl=$scheme://$http_host$request_uri;
    }
}

# Authly login server (can be on different subdomain)
server {
    listen 80;
    server_name auth.example.com;

    location / {
        proxy_pass http://authly:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy Configuration Example
```caddyfile
# Protected application
example.com {
    # Forward authentication to Authly
    forward_auth authly:8080 {
        uri /auth
        copy_headers X-Auth-User X-Auth-Email X-Auth-Name X-Auth-Roles X-Auth-Authenticated X-Auth-External
    }
    
    # Proxy to your application
    reverse_proxy your-app:3000
}

# Authly authentication server
auth.example.com {
    reverse_proxy authly:8080
}
```

### Traefik Configuration Example
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
      - "traefik.http.middlewares.authly-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email,X-Auth-Name,X-Auth-Roles,X-Auth-Authenticated,X-Auth-External"
```

### Application Integration

Your protected applications will receive user information through HTTP headers:

#### Headers Available
```
X-Auth-User: john.doe
X-Auth-Email: john.doe@company.com
X-Auth-Name: John Doe
X-Auth-UserId: user-123
X-Auth-Roles: admin,user
X-Auth-Authenticated: true
X-Auth-External: true
```

#### Example Application Code

**Node.js/Express:**
```javascript
app.use((req, res, next) => {
  req.user = {
    username: req.headers['x-auth-user'],
    email: req.headers['x-auth-email'],
    name: req.headers['x-auth-name'],
    userId: req.headers['x-auth-userid'],
    roles: req.headers['x-auth-roles']?.split(',') || [],
    authenticated: req.headers['x-auth-authenticated'] === 'true',
    external: req.headers['x-auth-external'] === 'true'
  };
  next();
});

// Check if user has specific role
function hasRole(req, role) {
  return req.user?.roles?.includes(role) || false;
}

// Check if user is admin
function isAdmin(req) {
  return hasRole(req, 'admin');
}
```

**Python/Flask:**
```python
from flask import request, g

@app.before_request
def load_user():
    g.user = {
        'username': request.headers.get('X-Auth-User'),
        'email': request.headers.get('X-Auth-Email'),
        'name': request.headers.get('X-Auth-Name'),
        'user_id': request.headers.get('X-Auth-UserId'),
        'roles': request.headers.get('X-Auth-Roles', '').split(','),
        'authenticated': request.headers.get('X-Auth-Authenticated') == 'true',
        'external': request.headers.get('X-Auth-External') == 'true'
    }

def has_role(role):
    return role in (g.user.get('roles') or [])

def is_admin():
    return has_role('admin')
```

**ASP.NET Core:**
```csharp
app.Use(async (context, next) =>
{
    var user = new
    {
        Username = context.Request.Headers["X-Auth-User"].FirstOrDefault(),
        Email = context.Request.Headers["X-Auth-Email"].FirstOrDefault(),
        Name = context.Request.Headers["X-Auth-Name"].FirstOrDefault(),
        UserId = context.Request.Headers["X-Auth-UserId"].FirstOrDefault(),
        Roles = context.Request.Headers["X-Auth-Roles"].FirstOrDefault()?.Split(',') ?? Array.Empty<string>(),
        Authenticated = context.Request.Headers["X-Auth-Authenticated"].FirstOrDefault() == "true",
        External = context.Request.Headers["X-Auth-External"].FirstOrDefault() == "true"
    };
    
    context.Items["User"] = user;
    await next();
});

// Extension method for role checking
public static bool HasRole(this HttpContext context, string role)
{
    if (context.Items["User"] is not dynamic user) return false;
    return ((string[])user.Roles).Contains(role);
}

public static bool IsAdmin(this HttpContext context)
{
    return context.HasRole("admin");
}
```

### Security Considerations

1. **Internal Network**: Ensure the `/auth` endpoint is only accessible from your reverse proxy, not from external clients
2. **HTTPS**: Always use HTTPS in production for both Authly and your applications
3. **Header Security**: Your applications should trust the authentication headers only when coming from your reverse proxy
4. **Cookie Domain**: Configure Authly's cookie domain to work across your subdomains if needed
5. **Session Security**: Consider the security implications of session sharing across applications
6. **OAuth Security**: Ensure proper redirect URI configuration for all OAuth providers
7. **IP Whitelisting**: Consider restricting access to Authly's admin endpoints

### Troubleshooting SSO

#### Check Authentication Status
```bash
# Test authentication endpoint directly
curl -I -b "cookies.txt" http://authly:8080/auth

# Get user information
curl -b "cookies.txt" http://authly:8080/auth/user

# Test OAuth endpoints
curl -I "http://authly:8080/google-login"
curl -I "http://authly:8080/microsoft-login"
curl -I "http://authly:8080/github-login"
```

#### Common Issues

1. **401 Unauthorized**: User not logged in or session expired
   - Check if user has valid session
   - Verify cookie domain and path settings
   - Check session timeout configuration

2. **403 Forbidden**: User locked out or insufficient permissions
   - Check user lockout status
   - Verify IP rate limiting isn't triggered
   - Check user roles and permissions

3. **500 Internal Server Error**: Check Authly logs for errors
   - Review Docker logs: `docker-compose logs authly`
   - Check OAuth configuration
   - Verify database connectivity

4. **Headers not passed**: Check reverse proxy configuration
   - Verify `auth_request_set` directives in nginx
   - Check `copy_headers` in Caddy
   - Ensure proper header forwarding in Traefik

5. **OAuth Issues**: 
   - Verify Client ID and Secret configuration
   - Check redirect URI configuration
   - Ensure proper domain setup for OAuth apps
   - Check OAuth provider-specific logs

6. **CORS issues**: Ensure proper CORS configuration if using AJAX
   - Configure allowed origins in Authly
   - Set proper headers for cross-origin requests

#### OAuth-Specific Troubleshooting

**Google OAuth:**
```bash
# Check Google OAuth configuration
echo $GOOGLE_CLIENT_ID
echo $AUTHLY_ENABLE_GOOGLE

# Test Google login flow
curl -I "http://authly:8080/google-login?returnUrl=/dashboard"
```

**Microsoft OAuth:**
```bash
# Check Microsoft OAuth configuration  
echo $MICROSOFT_CLIENT_ID
echo $MICROSOFT_TENANT_ID
echo $AUTHLY_ENABLE_MICROSOFT

# Test Microsoft login flow
curl -I "http://authly:8080/microsoft-login?returnUrl=/dashboard"
```

**GitHub OAuth:**
```bash
# Check GitHub OAuth configuration
echo $GITHUB_CLIENT_ID
echo $AUTHLY_ENABLE_GITHUB

# Test GitHub login flow
curl -I "http://authly:8080/github-login?returnUrl=/dashboard"
```

**Facebook OAuth:**
```bash
# Check Facebook OAuth configuration
echo $FACEBOOK_APP_ID
echo $AUTHLY_ENABLE_FACEBOOK

# Test Facebook login flow
curl -I "http://authly:8080/facebook-login?returnUrl=/dashboard"
```

#### Debug Logging

Enable debug logging for detailed OAuth troubleshooting:
```bash
export AUTHLY_DEBUG_LOGGING=true
docker-compose up -d

# Monitor OAuth-specific logs
docker-compose logs -f authly | grep -E "(OAuth|Login)"
```