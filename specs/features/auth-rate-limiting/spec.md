# Spec: Reverse Proxy Authentication Rate Limiting

## Status

- Status: approved
- Owner: TBD
- Created: 2026-05-18
- Updated: 2026-05-18
- Product source:
  - `prd.md`
  - `relatorio_tecnico.md`
- Related code:
  - `docs/operations/reverse-proxy.md`
  - `docs/README.md`
- Related specs:
  - `specs/contracts/security-session.md`
  - `specs/features/operational-observability/spec.md`
  - `specs/features/quality-testing/tavern-api-security.md`

## Intent

Document and require reverse-proxy-level throttling for public authentication
surfaces in hardened self-hosted deployments.

## Context

The product decision is to delegate rate limiting to the reverse proxy layer,
such as NGINX, Traefik, or an equivalent edge gateway. This keeps abusive traffic
away from the Python application before it reaches FastAPI, Authlib, SQLAlchemy,
LNURL callback handling, or email token logic.

Direct public exposure of SatOIDC without a throttling reverse proxy is not a
hardened production deployment shape.

## Scope

In scope:

- Password login attempts.
- Password registration submissions.
- Email verification resend and password reset request surfaces.
- LNURL callback attempts.
- Operator configuration examples for NGINX and Traefik.
- Warning language for direct exposure.
- Documentation for forwarded IP implications.

Out of scope:

- Full WAF behavior.
- Per-tenant quota management.
- In-app rate limiting.
- Requiring Redis for local development.
- Full WAF behavior or bot detection.

## Requirements

- Production documentation must state that SatOIDC relies on reverse-proxy rate
  limiting for hardened public exposure.
- Documentation must include examples for NGINX and Traefik when those proxies
  are used.
- Examples must cover login, registration, recovery, and LNURL callback paths,
  or explain when the proxy applies a router-wide limit.
- Documentation must warn that real client IP handling affects rate-limit keys.
- The app may later add in-app limits, but that is no longer required for the
  self-hosted MVP.

## Configuration

Recommended operator-managed limits:

- stricter limits for `POST /login`, `POST /register`, and password recovery;
- moderate limits for `GET /auth/lnurl/callback` to allow wallet retries while
  blocking bursts;
- separate limits per route where the proxy supports path-specific middleware;
- router-wide conservative limits where path-specific limits are not practical.

## Acceptance Criteria

- Given an operator reads the docs, then they see a clear alert that direct
  public exposure without edge rate limiting is not production-hardened.
- Given the operator uses NGINX, then the docs provide a `limit_req_zone` and
  `limit_req` example for SatOIDC auth paths.
- Given the operator uses Traefik, then the docs provide a `rateLimit`
  middleware example and explain router-wide versus path-specific limits.
- Given a reverse proxy is configured, then login/register/recovery/LNURL bursts
  are throttled before reaching SatOIDC.

## Test Plan

- Documentation review: examples are linked from `docs/README.md`.
- Manual operations: run an NGINX or Traefik deployment and verify bursts return
  proxy throttle responses.
- Future optional tests: add deployment-level smoke checks if the repository
  gains proxy fixtures.

## Open Questions

- Which proxy deployment should be used as the canonical production example?
- Should the Compose stack include optional NGINX or Traefik profiles later?
