# Known Issues And Technical Debt

Updated: 2026-05-18

## High Priority

No high-priority technical debt is currently tracked in this document. New
security or production-readiness findings should be added here before they are
split into specs or backlog items.

## Medium Priority

1. Keep an eye on README and examples encoding when editing from non-UTF-8 shell sessions.
2. Auth, OIDC, LNURL, and UI mutation failures need a minimal sanitized logging baseline for production operations.
3. `/oauth/token` has a container-backed PostgreSQL concurrency smoke and Locust seed/runbook support, but still needs a recorded PostgreSQL load result before production sizing decisions.
4. Production deployments must configure reverse-proxy rate limiting for public auth, recovery, and LNURL callback routes; direct public exposure is not hardened.

## Lower Priority

1. Keep new Markdown discoverable from `README.md`, `docs/README.md`, `specs/index.md`, or `agent-memory/index.md` to avoid orphan docs.

## Active Specs And Backlog

- See `docs/priority-execution-backlog.md` for the active task queue.
- See `specs/index.md` for current draft, review, approved, implemented and
  superseded specs.
- Completed backlog items are summarized in
  `docs/priority-execution-history.md`.
- The LNURL default nickname issue is historical/resolved; it should remain in
  completed-history sections only, not as an active risk.

## Recently Resolved Or Reduced

- Registration now has a dedicated `POST /register` endpoint that validates, creates the user, logs the user in, and sanitizes `redirect_to`.
- Schemas are centralized in `satoidc/satoidc/schemas/`; the old LNURL schema
  compatibility re-export was removed after confirming no imports used it.
- Default unit/integration coverage reached 100% on 2026-05-08 with browser e2e smoke tests still passing separately.
- Authlib metadata loading now uses `json.load()` for file handles instead of `json.loads()`.
- Client creation now has developer/admin permission enforcement, metadata validation, and one-time credential display.
- Profile nickname, email, password, and wallet unlink actions are implemented.
- Password login and LNURL redirect now sanitize `redirect_to` before navigation.
- Session cookie HTTPS behavior is environment-driven, and production mode rejects placeholder secrets.
- `LnurlAuthChallenge.consumed` now represents callback consumption before signature validation.
- OIDC signing keys are persisted, published with stable `kid` values, retained through validation windows, rotated through admin endpoints, and audited for lifecycle/signature events.
- Authenticated UI e2e coverage added via Playwright for home/profile, developer dashboard states, and create-client validation/success.
- Wallet link/relink functionality on the profile page is fully implemented using Native NiceGUI APIs.
- Developer OAuth client management (edit metadata, delete, rotate secret) is complete.
- Full browser OAuth authorization-code e2e coverage now exercises public PKCE and confidential client paths through login, consent, redirect, token exchange, ID Token, refresh token issuance, and UserInfo.
- `AuthMiddleware` public route matching now requires exact matches or path
  segment boundaries, preventing lookalike paths such as `/oauth-settings` or
  `/api-admin` from being exposed by prefix accident.
- The legacy root `relatorio.md` analysis was normalized to UTF-8 and archived
  under `docs/archive/` after its actionable findings were tracked elsewhere.
- OpenBao/Vault-compatible Transit signing is implemented and covered by a
  Testcontainers OpenBao integration test.
- Profile and OAuth client NiceGUI persistence actions were extracted into
  service helpers with focused unit coverage.
- Email verification and password recovery are implemented with hashed
  single-use tokens, SMTP/console/disabled sender modes, and Mailpit-backed
  integration coverage.
- SQLite and PostgreSQL migration support is covered by the database support
  matrix and PostgreSQL Testcontainers migration checks.
- The quality-testing task layer now includes unit, property, API security,
  integration, load, and aggregate commands.
- LNURL registration now uses the default nickname `satoshi` instead of
  attempting to create `User(nickname=None)`.
- Refresh token rotation, revoked access token behavior, introspection
  ownership, and UserInfo scope protection are covered by browser/client e2e
  token lifecycle tests.
