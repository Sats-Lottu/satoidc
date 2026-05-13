# Priority Execution Backlog

Updated: 2026-05-13

This backlog lists the highest-priority execution work found during the current
state review. It is ordered by security impact, product blocking value, and
implementation dependency.

## P0 - Security And Production Readiness

### 1. Persist And Rotate OIDC Signing Keys

Status: specified, not implemented.

Related specs:

- `specs/features/oidc-key-rotation/spec.md`
- `specs/flows/token-lifecycle.md`

Problem:

- The current RSA signing key is generated in memory at process startup.
- Existing ID tokens may become unverifiable after restart.
- Multiple replicas can publish inconsistent JWKS documents.

Expected outcome:

- Persist signing keys.
- Publish stable `kid` values in JWKS.
- Keep old public keys available while issued tokens may still be valid.
- Add audit events for key lifecycle and token signing.

### 2. Harden Login Redirect Safety

Status: implemented.

Related specs:

- `specs/contracts/security-session.md`
- `specs/flows/login.md`

Problem:

- Password registration sanitizes `redirect_to` with `safe_redirect`.
- Password login previously redirected to submitted `redirect_to` after
  successful authentication.

Expected outcome:

- `safe_redirect` is applied to password login and LNURL redirect navigation.
- Regression tests cover external URLs, host-relative URLs, empty values, and
  ordinary relative paths.

### 3. Make Session And Secrets Production-Aware

Status: implemented.

Related specs:

- `specs/contracts/runtime-config.md`
- `specs/flows/deployment.md`

Problem:

- Session cookies previously used a fixed `https_only=False`.
- Compose defaults include placeholder secrets and database credentials.
- There is no production secret manager integration.

Expected outcome:

- Environment-driven secure cookie settings.
- Fail-fast behavior for placeholder secrets in production mode.
- Documented production deployment baseline.

## P1 - Access Control And Admin Operations

### 4. Normalize Permission Taxonomy

Status: unresolved.

Related specs:

- `specs/contracts/database.md`
- `specs/features/permission-requests/spec.md`
- `specs/flows/page-security.md`

Problem:

- `PermissionsEnum` has `root`, `admin`, and `support`.
- UI and page-security checks also use `developer`.
- The database migration history and UI expectations are not fully aligned.

Expected outcome:

- Decide whether `developer` is a first-class enum value.
- Align models, migrations, seed/setup behavior, UI checks, tests, and docs.
- Keep `root` as all-powerful.

### 5. Implement Permission Requests

Status: specified, not implemented.

Related specs:

- `specs/features/permission-requests/spec.md`
- `specs/features/permission-requests/design.md`
- `specs/features/permission-requests/test-plan.md`

Problem:

- Profile still shows a placeholder developer access request action.
- Admin dashboard still shows static permission request content.

Expected outcome:

- Persist developer access requests.
- Notify admins in the dashboard.
- Allow admins to approve or deny with audit data.
- Grant developer access on approval.
- Add empty states, filters, pending counts, and useful admin summary widgets.

### 6. Complete Admin Dashboard Operational Views

Status: specified as part of permission requests, not implemented.

Related specs:

- `specs/features/permission-requests/spec.md`
- `specs/features/permission-requests/design.md`

Problem:

- Admin dashboard is not yet an operational console.

Expected outcome:

- Pending request count.
- Recent approvals/denials.
- Total users.
- Users with developer access.
- Registered OAuth clients.
- Recently created clients.
- Disabled or expired permissions.

## P2 - Account, LNURL, And Client Management

### 7. Rename LNURL Challenge State From Verified To Consumed

Status: implemented.

Related specs:

- `specs/flows/lnurl-auth.md`

Problem:

- The callback consumes the challenge before signature validation.
- This is intentional to prevent repeated attempts against the same challenge.
- The old field name `verified` suggested successful signature validation,
  which was not what the field meant.

Expected outcome:

- `LnurlAuthChallenge.consumed` is used in the model and callback queries.
- Migration, tests, and docs were updated.
- The current security behavior is preserved: a callback attempt consumes the
  challenge even if the signature is invalid.

### 8. Finish LNURL Wallet Link And Relink From Profile

Status: not implemented.

Related specs:

- `specs/flows/profile.md`
- `specs/flows/lnurl-auth.md`

Problem:

- Profile can unlink wallet when password login exists.
- Link and relink still show placeholder notifications.

Expected outcome:

- Add a QR/dialog flow for wallet link and relink.
- Reuse LNURL challenge TTL and event behavior.
- Ensure replay-safe challenge consumption.

### 9. Complete OAuth Client Management

Status: partially implemented.

Related specs:

- `specs/flows/client-registration.md`
- `specs/flows/home-and-client-console.md`

Problem:

- Client creation has validation and one-time credential display.
- Developer dashboard still lacks edit, delete/disable, and secret rotation.

Expected outcome:

- Edit client metadata.
- Disable or delete clients.
- Rotate client secrets.
- Add safe copy affordances for identifiers.
- Add integration and authenticated e2e coverage.

## P3 - Test Coverage And Documentation Quality

### 10. Add Full OAuth Browser E2E

Status: not implemented.

Related specs:

- `specs/flows/authorization-code.md`
- `specs/flows/token-lifecycle.md`
- `specs/flows/relying-party-examples.md`

Problem:

- Current e2e coverage focuses public pages and metadata endpoints.
- Full browser authorization-code flow with a real client is not covered.

Expected outcome:

- Exercise login, consent, redirect, code exchange, ID token, and UserInfo.
- Cover public client PKCE and confidential client paths.

### 11. Add Authenticated UI E2E

Status: not implemented.

Related specs:

- `specs/flows/profile.md`
- `specs/flows/client-registration.md`
- `specs/features/permission-requests/spec.md`

Problem:

- Profile, dashboard, and create-client authenticated workflows do not yet have
  browser e2e coverage.

Expected outcome:

- Profile rendering and mutation smoke checks.
- Developer dashboard empty and populated states.
- Create-client validation and successful creation.
- Admin permission request states after implementation.

### 12. Normalize Encoding And Documentation Drift

Status: ongoing.

Problem:

- Some shell sessions show mojibake in README/examples/legal docs.
- Several docs describe older placeholder state and must be kept aligned as
  implementation evolves.

Expected outcome:

- Normalize affected file encoding.
- Keep `README.md`, `docs/`, `specs/`, and `agent-memory/` synchronized.
