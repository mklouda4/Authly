# 🚀 Authly Docker Deployment Guide

> Complete guide for deploying Authly using Docker – from simple containers to production orchestration.

---

## 🐳 Deployment Options

### 1️⃣ Docker Standalone

Simple single container deployment:

```bash
# Build image
docker build -t authly:latest .

# Run container
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

---

### 2️⃣ Docker Compose (Recommended ✅)

Complete setup including UI for service health monitoring.

<details>
<summary><strong>📄 docker-compose.yml</strong></summary>

✅ Includes:
- Environment variables from `.env`
- OAuth configuration
- Healthcheck UI

```yaml
version: '3.8'

services:
  authly:
    image: authly:latest
    container_name: authly-app
    ports:
      - "8080:80"
      - "9090:9090"
    volumes:
      - authly_data:/app/wwwroot/data
      - authly_keys:/app/wwwroot/keys
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:80
      - ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
      - AUTHLY_NAME=${AUTHLY_NAME}
      - AUTHLY_DOMAIN=${AUTHLY_DOMAIN}
      - AUTHLY_BASE_URL=${AUTHLY_BASE_URL}
      - AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=${AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS}
      - AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=${AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS}
      - AUTHLY_ENABLE_METRICS=${AUTHLY_ENABLE_METRICS}
      - AUTHLY_ENABLE_GOOGLE=${AUTHLY_ENABLE_GOOGLE}
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  authly_data:
  authly_keys:
```
</details>

**Basic commands:**

```bash
docker-compose up -d              # Start
docker-compose logs -f            # Logs
docker-compose down               # Stop
docker-compose pull && docker-compose up -d  # Update
```

---

### 3️⃣ Portainer Stack

> Suitable for Portainer users. Use the configuration below as a Stack.

<details>
<summary><strong>📄 Stack YAML</strong></summary>

```yaml
version: '3.8'

services:
  authly:
    image: authly:latest
    container_name: authly-app
    ports:
      - "8080:80"
      - "9090:9090"
    volumes:
      - authly_data:/app/wwwroot/data
      - authly_keys:/app/wwwroot/keys
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:80
      - ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
      - AUTHLY_NAME=My Company Auth
      - AUTHLY_DOMAIN=your-domain.com
      - AUTHLY_BASE_URL=https://auth.your-domain.com
      - AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3
      - AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5
      - AUTHLY_ENABLE_METRICS=true
      - AUTHLY_ENABLE_GOOGLE=true
      - GOOGLE_CLIENT_ID=your-google-client-id
      - GOOGLE_CLIENT_SECRET=your-google-secret
    restart: unless-stopped

volumes:
  authly_data:
  authly_keys:
```
</details>

---

### 4️⃣ Configuration via `.env` file

Create a `.env` file with all variables:

```bash
AUTHLY_NAME=Authly
AUTHLY_DOMAIN=example.com
AUTHLY_BASE_URL=https://auth.example.com
AUTHLY_USER_LOCKOUT_MAX_ATTEMPTS=3
AUTHLY_IP_RATE_LIMIT_MAX_ATTEMPTS=5
AUTHLY_ENABLE_METRICS=true
AUTHLY_ENABLE_GOOGLE=true
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=GOCSPX-your-google-client-secret
```

> Useful for managing secrets outside of `docker-compose.yml`.

---

## 🔗 Single Sign-On (SSO)

Authly supports SSO via reverse proxy (nginx, Caddy, Traefik) using `auth_request`.

### 📌 Auth Endpoints

| Endpoint         | Method | Description                   | Response                |
|------------------|--------|-------------------------------|-------------------------|
| `/auth`          | GET    | Authentication verification   | `200`, `401`, `403`     |
| `/auth/user`     | GET    | Get user information          | JSON                    |
| `/auth/login`    | GET    | Redirect to login page        | Redirect                |

### ☁️ OAuth Endpoints

| Provider   | Login Endpoint       | Callback Endpoint              |
|------------|----------------------|--------------------------------|
| Google     | `/google-login`      | `/google/oauth2/callback`     |
| Microsoft  | `/microsoft-login`   | `/microsoft/oauth2/callback`  |
| GitHub     | `/github-login`      | `/github/oauth2/callback`     |
| Facebook   | `/facebook-login`    | `/facebook/oauth2/callback`   |

### 🔐 Response Headers

| Header              | Description              | Example            |
|---------------------|--------------------------|--------------------|
| `X-Auth-User`       | Username                 | `john.doe`         |
| `X-Auth-Email`      | Email address            | `john@example.com` |
| `X-Auth-UserId`     | Internal ID              | `user-123`         |
| `X-Auth-Roles`      | Roles (CSV)              | `admin,user`       |
| `X-Auth-Authenticated` | Authentication status | `true`             |
| `X-Auth-External`   | OAuth login              | `true`             |

---

## 🌐 Reverse Proxy Examples

### nginx

<details>
<summary><strong>nginx Configuration</strong></summary>

```nginx
upstream authly {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://authly;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Protected application
server {
    listen 443 ssl http2;
    server_name app.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Auth endpoint
    location = /auth {
        internal;
        proxy_pass http://authly/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Remote-Addr $remote_addr;
        proxy_set_header X-Original-Host $host;
    }
    
    location / {
        auth_request /auth;
        
        # Pass auth headers to backend
        auth_request_set $user $upstream_http_x_auth_user;
        auth_request_set $email $upstream_http_x_auth_email;
        proxy_set_header X-Auth-User $user;
        proxy_set_header X-Auth-Email $email;
        
        proxy_pass http://your-app-backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Redirect unauthorized users to login
    error_page 401 = @error401;
    location @error401 {
        return 302 https://auth.example.com/auth/login?returnUrl=$scheme://$http_host$request_uri;
    }
}
```
</details>

---

### Caddy

<details>
<summary><strong>Caddy Configuration</strong></summary>

```caddy
auth.example.com {
    reverse_proxy localhost:8080
}

app.example.com {
    forward_auth localhost:8080 {
        uri /auth
        copy_headers X-Auth-User X-Auth-Email X-Auth-Roles
    }
    reverse_proxy localhost:3000
}
```
</details>

---

### Traefik

<details>
<summary><strong>docker-compose + traefik.yml</strong></summary>

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.dashboard=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  authly:
    image: authly:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.authly.rule=Host(`auth.example.com`)"
      - "traefik.http.routers.authly.entrypoints=websecure"
      - "traefik.http.routers.authly.tls=true"
      - "traefik.http.services.authly.loadbalancer.server.port=80"
      
      # Auth middleware
      - "traefik.http.middlewares.authly-auth.forwardauth.address=http://authly/auth"
      - "traefik.http.middlewares.authly-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email,X-Auth-Roles"

  app:
    image: your-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.routers.app.entrypoints=websecure"
      - "traefik.http.routers.app.tls=true"
      - "traefik.http.routers.app.middlewares=authly-auth"
      - "traefik.http.services.app.loadbalancer.server.port=80"
```
</details>

---

## 🛠️ Application Integration

### 📥 Available Headers

```
X-Auth-User, X-Auth-Email, X-Auth-Name, X-Auth-UserId
X-Auth-Roles, X-Auth-Authenticated, X-Auth-External
Remote-User, Remote-Email, Remote-Name
```

---

### 📘 Integration Examples

#### Node.js (Express)

```js
const express = require('express');
const app = express();

app.use((req, res, next) => {
    // Get user info from headers
    req.authUser = {
        username: req.headers['x-auth-user'],
        email: req.headers['x-auth-email'],
        roles: req.headers['x-auth-roles']?.split(',') || [],
        authenticated: req.headers['x-auth-authenticated'] === 'true'
    };
    next();
});

app.get('/profile', (req, res) => {
    if (!req.authUser.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    res.json({
        user: req.authUser.username,
        email: req.authUser.email,
        roles: req.authUser.roles
    });
});

app.listen(3000);
```

#### Python (Flask)

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_auth_user():
    return {
        'username': request.headers.get('X-Auth-User'),
        'email': request.headers.get('X-Auth-Email'),
        'roles': request.headers.get('X-Auth-Roles', '').split(','),
        'authenticated': request.headers.get('X-Auth-Authenticated') == 'true'
    }

@app.route('/profile')
def profile():
    user = get_auth_user()
    
    if not user['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'user': user['username'],
        'email': user['email'],
        'roles': user['roles']
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
```

#### ASP.NET Core (C#)

```csharp
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ProfileController : ControllerBase
{
    [HttpGet]
    public IActionResult GetProfile()
    {
        var username = Request.Headers["X-Auth-User"].FirstOrDefault();
        var email = Request.Headers["X-Auth-Email"].FirstOrDefault();
        var roles = Request.Headers["X-Auth-Roles"].FirstOrDefault()?.Split(',') ?? Array.Empty<string>();
        var authenticated = Request.Headers["X-Auth-Authenticated"].FirstOrDefault() == "true";

        if (!authenticated)
        {
            return Unauthorized(new { error = "Not authenticated" });
        }

        return Ok(new
        {
            user = username,
            email = email,
            roles = roles
        });
    }
}

// Middleware for automatic user context
public class AuthHeaderMiddleware
{
    private readonly RequestDelegate _next;

    public AuthHeaderMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var username = context.Request.Headers["X-Auth-User"].FirstOrDefault();
        if (!string.IsNullOrEmpty(username))
        {
            var identity = new ClaimsIdentity("AuthProxy");
            identity.AddClaim(new Claim(ClaimTypes.Name, username));
            
            var email = context.Request.Headers["X-Auth-Email"].FirstOrDefault();
            if (!string.IsNullOrEmpty(email))
                identity.AddClaim(new Claim(ClaimTypes.Email, email));

            var roles = context.Request.Headers["X-Auth-Roles"].FirstOrDefault()?.Split(',');
            if (roles != null)
            {
                foreach (var role in roles)
                    identity.AddClaim(new Claim(ClaimTypes.Role, role.Trim()));
            }

            context.User = new ClaimsPrincipal(identity);
        }

        await _next(context);
    }
}
```

---

## 🧪 Development & Testing

### Local Development

```bash
dotnet restore
dotnet run --project Authly
```

> Access at `https://localhost:7283`

### Build

```bash
dotnet build -c Release
docker build -t authly:latest .
```

### Testing Auth Endpoints

```bash
# Test authentication
curl -I -b "cookies.txt" http://localhost:8080/auth

# Get user info
curl http://localhost:8080/auth/user

# Test with verbose output
curl -v -b "cookies.txt" http://localhost:8080/auth
```

---

## 🚨 Troubleshooting

### ✅ Quick Health Check

```bash
# Check if service is running
docker ps | grep authly

# Check logs
docker logs authly-app

# Test auth endpoint
curl -I http://localhost:8080/auth

# Test user endpoint
curl http://localhost:8080/auth/user
```

### 🛑 Common Issues

**Ports are occupied**
```bash
# Check what's using the port
netstat -tlnp | grep :8080
# or
lsof -i :8080
```

**OAuth misconfigured**
- Verify client ID and secret
- Check callback URLs match exactly
- Ensure OAuth provider is enabled

**Data directory permissions**
```bash
# Fix volume permissions
docker exec -it authly-app chown -R www-data:www-data /app/wwwroot/data
docker exec -it authly-app chown -R www-data:www-data /app/wwwroot/keys
```

**Reverse proxy issues**
- Check forwarded headers configuration
- Verify SSL termination setup
- Ensure auth_request module is enabled (nginx)

---

## 🔒 Security Recommendations

### ✅ Pre-deployment Checklist

- [ ] Change default login credentials
- [ ] Deploy with HTTPS (TLS certificate)
- [ ] Enable firewall and monitoring
- [ ] Verify lockout and rate-limiting settings
- [ ] Regular backup of data and keys
- [ ] Use Docker secrets or secure secret storage
- [ ] Review and limit OAuth permissions
- [ ] Enable audit logging
- [ ] Set up monitoring and alerting

### 👮‍♂️ Access Restrictions (e.g., LAN only)

```nginx
# Restrict admin interface
location /admin {
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    
    # Your normal proxy configuration
    proxy_pass http://authly;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
location /auth/login {
    limit_req zone=auth burst=3 nodelay;
    proxy_pass http://authly;
}
```

### 🔐 Environment Security

```bash
# Use Docker secrets instead of environment variables
echo "your-secret" | docker secret create google_client_secret -

# In docker-compose.yml
services:
  authly:
    secrets:
      - google_client_secret
    environment:
      - GOOGLE_CLIENT_SECRET_FILE=/run/secrets/google_client_secret

secrets:
  google_client_secret:
    external: true
```

---

## 📊 Monitoring & Metrics

### Prometheus Metrics

Authly exposes metrics on port `9090`:

```bash
# View available metrics
curl http://localhost:9090/metrics
```

### Docker Healthcheck

```bash
# Custom healthcheck
docker run --health-cmd="curl -f http://localhost:80/health || exit 1" \
           --health-interval=30s \
           --health-timeout=10s \
           --health-retries=3 \
           authly:latest
```

---

## 📌 Metadata

- **Guide Version:** 1.0.0  
- **Authly Version:** 1.0.0+  
- **Docker Required:** Yes  
- **Platforms:** Linux, Windows, macOS
- **Dependencies:** .NET 8.0, Docker, Reverse Proxy (optional)