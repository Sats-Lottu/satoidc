# Priority Execution History

Updated: 2026-05-18

This file summarizes completed execution backlog items. Keep active work in
`docs/priority-execution-backlog.md`.

## Completed On 2026-05-18

- Establish multiagent production-readiness execution plan.
  - Source: `docs/priority-execution-tasks/`
  - Outcome: production-readiness work was split into temporary task files for
    later subagent execution, with a multiagent execution strategy covering
    agent roles, model tiers, coordination, review, integration, branching,
    checkpoints, and anti-chaos controls.

- Complete Phase 0 contracts and CI foundation.
  - Source: `docs/priority-execution-tasks/phase-0-contracts-and-ci.md`
  - Outcome: runtime configuration docs now define current and future
    `SATOIDC_*` variable compatibility, precedence, `_FILE` expectations,
    secret flags, and migration notes; production deploy docs clarify that the
    current environment variable names remain the implemented interface today;
    PRD/spec/risk/backlog tracking was synchronized so resolved LNURL nickname
    work is no longer listed as active risk; quality task commands and markers
    were audited.
  - Validation: `cd satoidc; poetry run task test` passed with 242 selected
    tests, 21 deselected tests, and 5 warnings.

- Complete Phase 1 operator runbooks.
  - Source: `docs/priority-execution-tasks/phase-1-operations-runbooks.md`
  - Outcome: the operator runbook now covers PostgreSQL backup/restore, SQLite
    caveats, upgrades, Alembic failure handling, rollback expectations, health
    checks, and incident response; reverse-proxy operations now include TLS,
    forwarded-header, real-client-IP, NGINX, Traefik, path coverage, and manual
    burst-validation guidance; email and Transit operation docs now cover
    supported modes, required settings, troubleshooting, failure behavior, and
    production safety notes.
  - Validation: documentation links were checked by the execution agents, and
    `git diff --check` reported no whitespace errors for the changed operation
    docs.

- Retire duplicate Phase 1 observability task.
  - Source: `docs/priority-execution-tasks/phase-1-observability.md`
  - Outcome: the generated task file was removed from the active queue because
    `docs/priority-execution-history.md` already records the operational
    observability baseline as completed on or before 2026-05-17.

- Complete typed confirmation for OAuth client deletion.
  - Source: `docs/priority-execution-tasks/phase-2-admin-safety-scale.md`
  - Outcome: the developer dashboard delete dialog now requires typing the
    client display name before the destructive delete button becomes enabled.
    Focused browser coverage verifies disabled, wrong-text, enabled, deletion,
    and empty-state behavior.
  - Validation: `cd satoidc; poetry run ruff check satoidc/routes/dashboard.py
    tests/e2e/test_authenticated_ui_e2e.py` passed; `cd satoidc; poetry run
    pytest -m e2e
    tests/e2e/test_authenticated_ui_e2e.py::test_developer_dashboard_renders_client_actions
    -vv` passed.

- Complete admin dashboard pagination services.
  - Source: `docs/priority-execution-tasks/phase-2-admin-safety-scale.md`
  - Outcome: admin dashboard list queries for users, OAuth clients, permission
    requests, and inactive permissions now go through service helpers that
    return a stable `Page[T]` DTO with page metadata, total counts, boundary
    normalization, and optional filters. The admin route consumes these helpers
    with the current fixed defaults; responsive pagination controls remain a
    separate open UI task.
  - Validation: `cd satoidc; poetry run pytest
    tests/test_admin_dashboard_services.py tests/test_settings.py --no-cov -vv`
    passed; `cd satoidc; poetry run ruff check
    satoidc/services/admin_dashboard.py satoidc/routes/dashboard.py
    satoidc/runtime_config.py satoidc/settings.py
    tests/test_admin_dashboard_services.py tests/test_settings.py` passed;
    `cd satoidc; poetry run task test` passed with 257 selected tests, 21
    deselected tests, and 5 warnings.

- Complete runtime alias and `_FILE` configuration support.
  - Source: `docs/priority-execution-tasks/phase-3-setup-config-bootstrap.md`
  - Outcome: runtime settings now resolve documented `SATOIDC_*` aliases,
    support direct-over-file precedence for supported secret variables, support
    current `_FILE` names for compatible secrets, centralize URL and production
    secret validation, and provide a secret masking helper for setup and
    diagnostics. Setup state, non-interactive root bootstrap, and setup locking
    remain open.
  - Validation: `cd satoidc; poetry run pytest
    tests/test_admin_dashboard_services.py tests/test_settings.py --no-cov -vv`
    passed; `cd satoidc; poetry run ruff check
    satoidc/services/admin_dashboard.py satoidc/routes/dashboard.py
    satoidc/runtime_config.py satoidc/settings.py
    tests/test_admin_dashboard_services.py tests/test_settings.py` passed;
    `cd satoidc; poetry run task test` passed with 257 selected tests, 21
    deselected tests, and 5 warnings.

## Completed On Or Before 2026-05-17

- Implement email verification and account recovery.
  - Spec: `specs/features/email-verification/spec.md`
  - Outcome: users now have verified-email state, hashed single-use email
    verification and password reset tokens, profile resend support,
    enumeration-resistant recovery requests, reset-password flow, SMTP/console
    delivery abstraction, Mailpit/Testcontainers SMTP coverage, and
    `email_verified` in UserInfo for the `email` scope.

- Extract persistence-heavy route actions into services.
  - Spec: `specs/features/route-service-extraction/spec.md`
  - Outcome: profile account, password, email, wallet-link, and wallet-unlink
    mutations now live in profile service helpers; OAuth client creation,
    metadata updates, secret rotation, status toggles, and deletion now live in
    OAuth client services; route modules translate UI values and notifications
    without owning persistence logic. Unit tests cover the extracted service
    behavior, and JWKS ordering now keeps the active key first after backend
    switches.

- Add OpenBao-compatible external signing backend.
  - Spec: `specs/features/external-signing-backend/spec.md`
  - Outcome: OIDC signing supports `database` and Vault-compatible `transit`
    backends, Transit key versions are recorded in signing-key metadata,
    ID Tokens can be signed through OpenBao without private key material in
    SatOIDC, and Testcontainers coverage verifies the real OpenBao Transit
    path.

- Refactor application setup bootstrap.
  - Spec: `specs/features/application-setup/spec.md`
  - Outcome: container startup validates runtime configuration before
    migrations, can persist generated-owned secrets to an approved
    `SETUP_GENERATED_SECRETS_PATH` without logging values, reloads those
    generated secrets before importing the app, and validates database-backed
    root permission plus OIDC signing-key readiness before starting SatOIDC.

- Refactor test layer for quality specs.
  - Specs: `specs/features/quality-testing/spec.md`,
    `specs/features/quality-testing/pytest-extensions.md`,
    `specs/features/quality-testing/hypothesis-property.md`,
    `specs/features/quality-testing/tavern-api-security.md`,
    `specs/features/quality-testing/playwright-ui.md`,
    `specs/features/quality-testing/locust-load.md`,
    `specs/features/quality-testing/testcontainers-integration.md`
  - Outcome: pytest markers and taskipy commands now cover unit, property, API
    security, integration, e2e, load, and non-load suites; Hypothesis covers
    redirect/validator invariants; Python and Tavern API smoke tests cover
    public metadata and route-boundary contracts; integration coverage uses
    Testcontainers for PostgreSQL migrations and token issuance; Locust has a
    bounded public-route smoke scenario.

- Add lightweight load/concurrency checks for token issuance.
  - Specs: `specs/contracts/authlib-adapter.md`,
    `specs/flows/token-lifecycle.md`
  - Outcome: `test_integration` now includes a PostgreSQL/Testcontainers smoke
    that applies migrations, starts SatOIDC against PostgreSQL, seeds a public
    PKCE client with unique authorization codes, and exchanges them
    concurrently through `/oauth/token`.

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
