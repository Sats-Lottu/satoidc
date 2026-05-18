# Reverse Proxy Operations

Updated: 2026-05-18

SatOIDC expects production deployments to run behind a TLS-terminating reverse
proxy such as NGINX or Traefik.

## Rate Limiting Responsibility

Rate limiting is delegated to the reverse proxy layer for production
deployments. This keeps abusive traffic away from the Python application before
it reaches FastAPI, Authlib, SQLAlchemy, LNURL callback handling, or email token
logic.

Important alert:

- If SatOIDC is exposed directly without NGINX, Traefik, or equivalent edge
  throttling, public authentication routes do not have the intended production
  rate-limit protection.
- Configure rate limits for at least:
  - `POST /login`
  - `POST /register`
  - `GET /auth/lnurl/callback`
  - password recovery and verification resend routes
- Rate-limit keys depend on real client IPs. If SatOIDC is behind multiple
  proxies, configure trusted proxy headers carefully so all users are not
  grouped under a single proxy IP.
- Treat the values below as conservative starting points. Tune them with logs
  and real traffic.

## NGINX Example

NGINX rate limiting uses a shared zone declared with `limit_req_zone` and then
applies that zone to selected `location` blocks with `limit_req`.

```nginx
http {
    limit_req_zone $binary_remote_addr zone=satoidc_auth:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=satoidc_lnurl:10m rate=30r/m;

    server {
        listen 443 ssl http2;
        server_name id.example.com;

        location = /login {
            limit_req zone=satoidc_auth burst=5 nodelay;
            proxy_pass http://satoidc:8000;
        }

        location = /register {
            limit_req zone=satoidc_auth burst=5 nodelay;
            proxy_pass http://satoidc:8000;
        }

        location = /forgot-password {
            limit_req zone=satoidc_auth burst=3 nodelay;
            proxy_pass http://satoidc:8000;
        }

        location = /auth/lnurl/callback {
            limit_req zone=satoidc_lnurl burst=10 nodelay;
            proxy_pass http://satoidc:8000;
        }

        location / {
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_pass http://satoidc:8000;
        }
    }
}
```

## Traefik Example

Traefik exposes rate limiting as an HTTP middleware. Attach the middleware to
the SatOIDC router that receives public traffic.

Docker label example:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.satoidc.rule=Host(`id.example.com`)"
  - "traefik.http.routers.satoidc.entrypoints=websecure"
  - "traefik.http.routers.satoidc.tls=true"
  - "traefik.http.routers.satoidc.middlewares=satoidc-auth-ratelimit"
  - "traefik.http.middlewares.satoidc-auth-ratelimit.ratelimit.average=10"
  - "traefik.http.middlewares.satoidc-auth-ratelimit.ratelimit.period=1m"
  - "traefik.http.middlewares.satoidc-auth-ratelimit.ratelimit.burst=20"
```

Static/dynamic YAML example:

```yaml
http:
  middlewares:
    satoidc-auth-ratelimit:
      rateLimit:
        average: 10
        period: 1m
        burst: 20
```

Traefik middleware matching is usually router-wide. If you need different limits
for login, registration, recovery, and LNURL callback paths, define separate
routers with path rules and attach different `rateLimit` middlewares.

## References

- NGINX request limiting documentation:
  https://docs.nginx.com/nginx/admin-guide/security-controls/controlling-access-proxied-http/
- NGINX `limit_req` module reference:
  https://nginx.org/r/limit_req_zone
- Traefik RateLimit middleware:
  https://doc.traefik.io/traefik/v2.11/middlewares/http/ratelimit/
