# Known Issues And Technical Debt

Updated: 2026-05-13

## High Priority

1. JWT signing key is generated in memory at startup, making JWKS unstable across restarts and replicas.
2. OIDC signing key rotation is specified but not implemented; production still needs persistent key material, `kid` handling, retention windows, admin authorization and audit events.
3. Full browser OAuth authorization-code e2e coverage is still partial; current e2e tests are public-page and endpoint smoke/responsive checks.
4. `login_post` does not sanitize `redirect_to` with `safe_redirect`; registration now does, but login still needs the same redirect hardening.

## Medium Priority

1. Permission taxonomy is inconsistent between enum, migration, dashboard, profile checks, and intended developer access.
2. `LnurlAuthChallenge.verified` is a misleading field name. The challenge is intentionally consumed before signature verification as a replay-defense measure, even when the signature is invalid; the field should be renamed to something like `consumed`.
3. LNURL registration can create `User(nickname=None)` even though `nickname` is non-nullable.
4. Refresh token support has focused unit/integration tests, but still needs broader end-to-end client-flow coverage.
5. README and examples may show mojibake in some shell sessions.

## Lower Priority

1. Admin dashboard still contains static permission request content.
2. Wallet link/relink and developer permission requests from profile are placeholders.
3. Client management lacks edit, delete/disable, and secret rotation actions.
4. Production cookie and HTTPS settings need hardening.
5. Keep new Markdown discoverable from `README.md`, `docs/README.md`, `specs/index.md`, or `agent-memory/index.md` to avoid orphan docs.

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
