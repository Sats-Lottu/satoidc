# Known Issues And Technical Debt

Updated: 2026-05-13

## High Priority

1. Full browser OAuth authorization-code e2e coverage is still partial; current e2e tests are public-page and endpoint smoke/responsive checks.
2. Vault Transit remains a future hardening step for OIDC signing keys; the MVP persists private key material encrypted in the database.

## Medium Priority

1. Permission taxonomy is inconsistent between enum, migration, dashboard, profile checks, and intended developer access.
2. LNURL registration can create `User(nickname=None)` even though `nickname` is non-nullable.
3. Refresh token support has focused unit/integration tests, but still needs broader end-to-end client-flow coverage.
4. README and examples may show mojibake in some shell sessions.

## Lower Priority

1. Admin dashboard still contains static permission request content.
2. Wallet link/relink and developer permission requests from profile are placeholders.
3. Client management lacks edit, delete/disable, and secret rotation actions.
4. Keep new Markdown discoverable from `README.md`, `docs/README.md`, `specs/index.md`, or `agent-memory/index.md` to avoid orphan docs.

## Suggested First Specs

- `login-redirect-safety`
- `oidc-key-rotation` is drafted in `specs/features/oidc-key-rotation/`; implementation is still pending.
- `permissions-model`
- `lnurl-challenge-state-rename`
- `oidc-discovery-contract`

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
