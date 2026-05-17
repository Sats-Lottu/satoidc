# Priority Execution History

Updated: 2026-05-17

This file summarizes completed execution backlog items. Keep active work in
`docs/priority-execution-backlog.md`.

## Completed On Or Before 2026-05-17

- Validate SQLite and PostgreSQL support matrix.
  - Specs: `specs/contracts/database.md`,
    `specs/contracts/runtime-config.md`, `specs/flows/deployment.md`
  - Outcome: runtime settings validate async/sync database URL pairs, focused
    tests cover SQLite and PostgreSQL URL matching rules, PostgreSQL 16
    Testcontainers coverage applies Alembic migrations to `head`, and
    `docs/database-support-matrix.md` documents supported database pairings.

- Remove LNURL schema compatibility shim and archive legacy report.
  - Reference: `docs/changes-2026-05-08.md`
  - Outcome: no code or tests import
    `satoidc.satoidc.auth.lnurl_schemas`; the compatibility re-export was
    removed, and the legacy root `relatorio.md` was normalized to UTF-8 and
    archived as `docs/archive/legacy-analysis-report.md`.

- Add operational observability baseline.
  - Spec: `specs/features/operational-observability/spec.md`
  - Outcome: auth middleware redirects, OAuth authorization failures, LNURL
    callback failures, OIDC signing/key-admin failures, permission-request
    failures, and client-secret mutation failures emit sanitized operational
    logs with regression coverage for passwords, tokens, private JWKs, wallet
    signatures, and client secrets.

- Harden public route boundary matching.
  - Spec: `specs/features/public-route-boundary/spec.md`
  - Outcome: middleware public path checks now require exact paths or path
    segment boundaries, with regression coverage for lookalike protected paths
    such as `/oauth-settings`, `/api-admin`, and `/.well-knownness`.

- Persist and rotate OIDC signing keys.
  - Spec: `specs/features/oidc-key-rotation/spec.md`
  - Outcome: signing keys are persisted, JWTs use stable `kid` headers, JWKS
    publishes active/validating keys, and key lifecycle audit events exist.

- Harden login redirect safety.
  - Specs: `specs/contracts/security-session.md`, `specs/flows/login.md`
  - Outcome: password login and LNURL redirect navigation use `safe_redirect`
    with regression coverage for unsafe targets.

- Make sessions and secrets production-aware.
  - Specs: `specs/contracts/runtime-config.md`, `specs/flows/deployment.md`
  - Outcome: runtime configuration covers secure cookies, placeholder-secret
    checks, and production deployment guidance.

- Normalize permission taxonomy.
  - Specs: `specs/contracts/database.md`,
    `specs/features/permission-requests/spec.md`,
    `specs/flows/page-security.md`
  - Outcome: `developer` is a first-class permission and `root` remains
    all-powerful.

- Implement permission requests.
  - Spec: `specs/features/permission-requests/spec.md`
  - Outcome: users can request developer access and admins can approve or deny
    requests with persisted audit data.

- Complete admin dashboard operational views.
  - Spec: `specs/features/permission-requests/design.md`
  - Outcome: admin dashboard shows pending requests, recent approvals, user
    counts, client counts, and permission state.

- Rename LNURL challenge state from verified to consumed.
  - Spec: `specs/flows/lnurl-auth.md`
  - Outcome: challenge consumption semantics match replay-defense behavior even
    when signature validation fails.

- Finish LNURL wallet link and relink from profile.
  - Specs: `specs/flows/profile.md`, `specs/flows/lnurl-auth.md`
  - Outcome: profile supports wallet link, relink, and unlink with QR-based
    LNURL-auth flows.

- Complete OAuth client management.
  - Specs: `specs/flows/client-registration.md`,
    `specs/flows/home-and-client-console.md`
  - Outcome: developer dashboard supports client edit, disable/delete, secret
    rotation, identifier copy, and related tests.

- Add full OAuth browser e2e.
  - Specs: `specs/flows/authorization-code.md`,
    `specs/flows/token-lifecycle.md`,
    `specs/flows/relying-party-examples.md`
  - Outcome: e2e coverage exercises login, consent, code exchange, ID Token,
    refresh token issuance, and UserInfo.

- Add authenticated UI e2e.
  - Specs: `specs/flows/profile.md`,
    `specs/flows/client-registration.md`,
    `specs/features/permission-requests/spec.md`
  - Outcome: e2e coverage includes signed-in profile, wallet-link QR smoke,
    developer dashboard states, create-client flows, and admin approval.

- Normalize encoding and documentation drift.
  - Outcome: README, docs, specs, and agent memory were synchronized with the
    completed priority backlog state.
