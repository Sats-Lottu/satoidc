# Spec: Public Route Boundary Hardening

## Status

- Status: draft
- Owner: TBD
- Created: 2026-05-16
- Updated: 2026-05-16
- Related code:
  - `satoidc/satoidc/auth/middleware.py`
  - `satoidc/tests/`
- Related specs:
  - `specs/contracts/security-session.md`
  - `specs/flows/page-security.md`

## Intent

Make the authentication middleware's public route boundary explicit, testable,
and resistant to accidental exposure when new protected routes are added.

## Context

`AuthMiddleware` currently allows exact public paths and broad public prefixes
such as `/oauth` and `/api` through `path.startswith(PUBLIC_PREFIXES)`.

That is convenient, but it can accidentally expose a future protected route
whose name only shares a prefix, for example `/oauth-settings`.

## Scope

In scope:

- Replace broad prefix matching with boundary-aware matching.
- Keep current legitimate public endpoints public.
- Add regression tests for lookalike protected paths.
- Document how future public routes should be registered.

Out of scope:

- Redesigning page-level permission checks.
- Changing OAuth/OIDC endpoint behavior.
- Adding a new router framework or middleware package.

## Rules

- Exact public paths remain explicit.
- Public prefixes must match either the prefix itself or a path segment below it.
- `/oauth-settings`, `/api-admin`, `/.well-knownness`, and similar lookalikes
  must not be public by prefix accident.
- Static NiceGUI assets remain public.
- Missing-session redirects must preserve the requested path and query string.

## Flows

### Protected Lookalike Path

1. A browser requests `/oauth-settings` without a session.
2. The middleware checks exact public paths and boundary-aware prefixes.
3. The path is not considered public.
4. The browser is redirected to `/login?redirect_to=/oauth-settings`.

### Legitimate Public Path

1. A client requests `/oauth/token`.
2. The middleware recognizes `/oauth` as a public segment boundary.
3. The request reaches the OAuth route unchanged.

## Contracts

- Authentication middleware path classification.
- Redirect behavior for missing sessions.
- Security session contract public path list.

## Acceptance Criteria

- Given `/oauth/token`, when requested without a session, then the request is
  not redirected by `AuthMiddleware`.
- Given `/oauth-settings`, when requested without a session, then the request is
  redirected to login.
- Given `/api/status`, when requested without a session, then the request is not
  redirected if the route is intended public.
- Given `/api-admin`, when requested without a session, then the request is
  redirected to login.
- Given `/.well-known/openid-configuration`, when requested without a session,
  then the request is not redirected.
- Given `/.well-knownness`, when requested without a session, then the request
  is redirected to login.

## Test Plan

- Unit: helper tests for exact and boundary-aware public path classification.
- Integration: middleware tests for redirect and pass-through behavior.
- UI/manual: direct browser check for protected lookalike paths.
- Security/regression: ensure OAuth, LNURL, discovery, and NiceGUI asset paths
  still work without a session.

## Implementation Notes

Prefer a small pure helper such as `is_public_path(path: str) -> bool`, covered
by focused tests. Avoid route-name inference or framework internals unless the
existing routing style changes.

## Traceability

- Code: `satoidc/satoidc/auth/middleware.py`
- Tests: `satoidc/tests/`
- Docs: `docs/priority-execution-backlog.md`
- Decisions: `agent-memory/decisions.md`
