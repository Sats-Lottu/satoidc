# Reverse Proxy Operations

Updated: 2026-05-18

SatOIDC expects production deployments to run behind a TLS-terminating reverse
proxy such as NGINX, Traefik, or an equivalent edge gateway.

Direct public exposure without edge throttling is not a hardened production
deployment shape. SatOIDC delegates public authentication rate limiting to the
reverse proxy so abusive traffic is rejected before it reaches FastAPI, Authlib,
SQLAlchemy, LNURL callback handling, or email token logic.

## Required Public Controls

Hardened production deployments must provide these controls at the edge:

- TLS on the public issuer host. `OAUTH2_JWT_ISS` and
  `EMAIL_PUBLIC_BASE_URL` must use the same public HTTPS origin unless an
  operator intentionally separates them.
- Redirect HTTP to HTTPS and serve HSTS after the deployment is verified.
- Forward `Host`, `X-Forwarded-Proto`, and `X-Forwarded-For` to SatOIDC.
- Preserve the real client IP for rate-limit keys and logs. Do not trust
  client-supplied forwarding headers from the public internet.
- Apply rate limits to public authentication and token-consumption paths before
  proxying to the application.

## Public Auth Surfaces

Apply edge limits to these current public paths:

| Path | Method | Suggested starting point | Notes |
| --- | --- | --- | --- |
| `/login` | `POST` | 5 requests/minute, burst 5 | Password login submission. Avoid throttling the `GET` page too tightly because it loads the QR login screen. |
| `/register` | `POST` | 5 requests/minute, burst 5 | Password registration submission. |
| `/forgot-password` | `POST` | 3 requests/minute, burst 3 | Password recovery email request. |
| `/reset-password` | `POST` | 3 requests/minute, burst 3 | Password reset token submission. |
| `/verify-email` | `GET` | 10 requests/minute, burst 10 | Email verification token consumption. There is no separate verification-resend route in the current app. |
| `/auth/lnurl/callback` | `GET` | 30 requests/minute, burst 10 | LNURL wallet callback. Allow wallet retries but block bursts. |

These are conservative starting points. Tune them with access logs, proxy
rejection counts, and support feedback. If a proxy cannot express per-path
limits, use a router-wide limit strict enough to protect these routes without
breaking OIDC discovery, JWKS, static assets, and normal page navigation.

## Forwarded Headers And Real IP

The rate-limit key must identify the real client, not only the proxy container
or load balancer. A common failure mode is grouping every user under one proxy
IP, which causes false-positive lockouts, or trusting arbitrary
`X-Forwarded-For`, which lets attackers choose their own rate-limit key.

Use these rules:

- The public edge should overwrite forwarding headers received from clients.
- If another trusted load balancer sits in front of NGINX or Traefik, configure
  that proxy's trusted source ranges explicitly.
- Keep trusted ranges narrow: use the private subnet, Cloudflare/AWS/GCP load
  balancer ranges, or Compose network CIDRs that actually send traffic to the
  proxy.
- Confirm proxy access logs include a real client address before testing rate
  limits.

SatOIDC also uses configured public URLs for protocol metadata. Forwarded
headers help request handling, but they do not replace setting
`OAUTH2_JWT_ISS=https://id.example.com` and production HTTPS-only cookies.

## NGINX Example

This example limits only mutating password-auth form submissions for `/login`,
`/register`, `/forgot-password`, and `/reset-password`, while separately
limiting email verification and LNURL callback token consumption.

If NGINX is directly internet-facing, `$binary_remote_addr` is already the
client IP. If NGINX is behind a trusted load balancer, enable `real_ip` first so
`$binary_remote_addr` is derived from the real client address.

```nginx
http {
    # Only trust addresses that are allowed to set X-Forwarded-For.
    # Replace these examples with your load balancer or private network CIDRs.
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    map $request_method $satoidc_post_limit_key {
        default "";
        POST $binary_remote_addr;
    }

    limit_req_zone $satoidc_post_limit_key zone=satoidc_auth:10m rate=5r/m;
    limit_req_zone $satoidc_post_limit_key zone=satoidc_recovery:10m rate=3r/m;
    limit_req_zone $binary_remote_addr zone=satoidc_token_get:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=satoidc_lnurl:10m rate=30r/m;
    limit_req_status 429;

    server {
        listen 80;
        server_name id.example.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name id.example.com;

        ssl_certificate /etc/letsencrypt/live/id.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/id.example.com/privkey.pem;
        add_header Strict-Transport-Security "max-age=31536000" always;

        location = /login {
            limit_req zone=satoidc_auth burst=5 nodelay;
            include snippets/satoidc-proxy-headers.conf;
            proxy_pass http://satoidc:8000;
        }

        location = /register {
            limit_req zone=satoidc_auth burst=5 nodelay;
            include snippets/satoidc-proxy-headers.conf;
            proxy_pass http://satoidc:8000;
        }

        location = /forgot-password {
            limit_req zone=satoidc_recovery burst=3 nodelay;
            include snippets/satoidc-proxy-headers.conf;
            proxy_pass http://satoidc:8000;
        }

        location = /reset-password {
            limit_req zone=satoidc_recovery burst=3 nodelay;
            include snippets/satoidc-proxy-headers.conf;
            proxy_pass http://satoidc:8000;
        }

        location = /verify-email {
            limit_req zone=satoidc_token_get burst=10 nodelay;
            include snippets/satoidc-proxy-headers.conf;
            proxy_pass http://satoidc:8000;
        }

        location = /auth/lnurl/callback {
            limit_req zone=satoidc_lnurl burst=10 nodelay;
            include snippets/satoidc-proxy-headers.conf;
            proxy_pass http://satoidc:8000;
        }

        location / {
            include snippets/satoidc-proxy-headers.conf;
            proxy_pass http://satoidc:8000;
        }
    }
}
```

Suggested `snippets/satoidc-proxy-headers.conf`:

```nginx
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;
```

NGINX notes:

- Requests with an empty `limit_req_zone` key are not counted, so the `map`
  avoids rate limiting `GET /login` and `GET /register` in this example.
- Use `limit_req_dry_run on;` briefly if you need to observe would-be rejects
  before enforcing limits.
- Make 429 responses visible in access logs and alerts.

## Traefik Example

Traefik exposes rate limiting as an HTTP middleware. The middleware is usually
router-wide, so the simplest configuration attaches one conservative auth limit
to a router that matches the public auth paths.

Docker label example:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.satoidc-auth.rule=Host(`id.example.com`) && (((Path(`/login`) || Path(`/register`) || Path(`/forgot-password`) || Path(`/reset-password`)) && Method(`POST`)) || Path(`/verify-email`) || Path(`/auth/lnurl/callback`))"
  - "traefik.http.routers.satoidc-auth.entrypoints=websecure"
  - "traefik.http.routers.satoidc-auth.tls=true"
  - "traefik.http.routers.satoidc-auth.middlewares=satoidc-auth-ratelimit"
  - "traefik.http.routers.satoidc-auth.service=satoidc"
  - "traefik.http.services.satoidc.loadbalancer.server.port=8000"
  - "traefik.http.middlewares.satoidc-auth-ratelimit.ratelimit.average=10"
  - "traefik.http.middlewares.satoidc-auth-ratelimit.ratelimit.period=1m"
  - "traefik.http.middlewares.satoidc-auth-ratelimit.ratelimit.burst=20"
  - "traefik.http.middlewares.satoidc-auth-ratelimit.ratelimit.sourcecriterion.ipstrategy.excludedips=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
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
        sourceCriterion:
          ipStrategy:
            excludedIPs:
              - "10.0.0.0/8"
              - "172.16.0.0/12"
              - "192.168.0.0/16"
```

Traefik notes:

- If Traefik is directly internet-facing, the default remote-address source is
  normally enough. Configure `sourceCriterion.ipStrategy` only when Traefik is
  behind known trusted proxies.
- `excludedIPs` is not a rate-limit bypass list. It tells Traefik which trusted
  proxy IPs to skip while finding the client address in `X-Forwarded-For`.
- If you need separate limits, define separate routers: one for password form
  submissions, one for `/verify-email`, and one for `/auth/lnurl/callback`.
- If your Traefik deployment cannot use method-aware router rules, attach the
  middleware to path-only auth routers and tune the limits so `GET /login`,
  `GET /register`, and recovery pages remain usable.
- Keep a lower-priority catch-all SatOIDC router for discovery, JWKS, assets,
  normal pages, and OAuth flows that should not share the strict auth bucket.

## Manual Validation Checklist

Run this against a disposable proxy or a low-risk staging deployment before
serving production traffic.

1. Confirm HTTPS and metadata:

   ```bash
   curl --fail --show-error https://id.example.com/.well-known/openid-configuration
   curl --fail --show-error https://id.example.com/.well-known/jwks.json
   curl --head --silent --show-error http://id.example.com/
   ```

   The issuer and endpoint URLs must be `https://id.example.com/...`, JWKS must
   return public key material, and HTTP should redirect to HTTPS.

2. Confirm normal pages still load:

   ```bash
   curl --fail --show-error https://id.example.com/login
   curl --fail --show-error https://id.example.com/register
   ```

3. Confirm burst requests are rejected by the proxy before SatOIDC handles all
   of them. Adjust the loop count above your configured burst:

   ```bash
   for i in $(seq 1 12); do
     curl -k -o /dev/null -s -w "%{http_code}\n" \
       -X POST https://id.example.com/login \
       -H "Content-Type: application/x-www-form-urlencoded" \
       --data "username=invalid&password=invalid"
   done
   ```

   Expected result: early responses may be application redirects or validation
   responses, then the proxy returns 429 or its configured throttle status.

4. Repeat with `/register`, `/forgot-password`, `/reset-password`,
   `/verify-email?token=invalid`, and
   `/auth/lnurl/callback?tag=login&k1=invalid&key=invalid&sig=invalid&action=login`.

5. Confirm real-IP behavior:

   - Proxy access logs show the test client address, not only the SatOIDC
     container, NGINX, Traefik, or load-balancer address.
   - Two different client IPs do not immediately consume one shared bucket.
   - A request with a spoofed public `X-Forwarded-For` header does not bypass
     the limit unless it comes from a trusted upstream proxy.

6. Confirm proxy logs and metrics expose throttle events clearly enough for
   incident triage.

## References

- NGINX request limiting documentation:
  https://docs.nginx.com/nginx/admin-guide/security-controls/controlling-access-proxied-http/
- NGINX `limit_req` module reference:
  https://nginx.org/en/docs/http/ngx_http_limit_req_module.html
- NGINX real IP module reference:
  https://nginx.org/en/docs/http/ngx_http_realip_module.html
- Traefik RateLimit middleware:
  https://doc.traefik.io/traefik/v2.11/middlewares/http/ratelimit/
