# Known Issues And Technical Debt

Updated: 2026-05-16

## High Priority

1. OpenBao/Vault-compatible Transit remains a future hardening step for OIDC signing keys; the MVP persists private key material encrypted in the database and must warn about the combined database plus runtime-secret compromise risk.

## Medium Priority

1. LNURL registration can create `User(nickname=None)` even though `nickname` is non-nullable.
2. Refresh token revocation has focused unit/integration tests, but still needs broader end-to-end client-flow coverage.
3. Keep an eye on README and examples encoding when editing from non-UTF-8 shell sessions.
4. Persistence-heavy NiceGUI route actions should be extracted into testable service/use-case helpers.
5. Auth, OIDC, LNURL, and UI mutation failures need a minimal sanitized logging baseline for production operations.
6. `/oauth/token` needs lightweight load/concurrency checks because Authlib SQLAlchemy operations are synchronous behind threadpool helpers.
7. SQLite and PostgreSQL support should be validated as an explicit matrix so migrations and sync/async database URLs do not drift.

## Lower Priority

1. Keep new Markdown discoverable from `README.md`, `docs/README.md`, `specs/index.md`, or `agent-memory/index.md` to avoid orphan docs.
2. Remove the legacy `satoidc/satoidc/auth/lnurl_schemas.py` compatibility shim when downstream imports no longer need it.
3. Normalize or archive `relatorio.md`, which currently contains mojibake and duplicates tracked state.

## Active Specs And Backlog

- See `docs/priority-execution-backlog.md` for the active task queue.
- See `specs/index.md` for current draft, review, approved, implemented and
  superseded specs.
- Completed backlog items are summarized in
  `docs/priority-execution-history.md`.

## Recently Resolved Or Reduced

- Registration now has a dedicated `POST /register` endpoint that validates, creates the user, logs the user in, and sanitizes `redirect_to`.
- Schemas are centralized in `satoidc/satoidc/schemas/`, with a compatibility re-export for the old LNURL schema path.
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
