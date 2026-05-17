# Priority Execution Backlog

Updated: 2026-05-17

This backlog is a temporary queue for open execution work. Completed items must
be removed from this file and summarized in `docs/priority-execution-history.md`.

## Open Items

### 1. Refactor Application Setup Bootstrap

Status: in progress.

Spec:

- `specs/features/application-setup/spec.md`

Expected outcome:

- Refactor setup so fresh deployments validate or generate every required
  runtime value before the main app starts, including safe secret/token
  generation, root-user bootstrap, database readiness, OIDC signing readiness,
  and actionable messages for values that must remain managed by Coolify or the
  process environment.

Progress:

- Bootstrap configuration validation now runs before migrations in the
  container entrypoint.
- Bootstrap now checks database connectivity before migrations.
- Production startup reports actionable blocks for placeholder generated
  secrets, missing/local issuer configuration, insecure session cookies, and
  async/sync database URL mismatches without printing secret values.

Remaining:

- Add an approved persistence path for generated secrets.
- Fold root-user and OIDC signing-key readiness into the same bootstrap report.

### 2. Add OpenBao-Compatible External Signing Backend

Status: draft.

Spec:

- `specs/features/external-signing-backend/spec.md`

Expected outcome:

- Add a signing backend interface and a Vault-compatible Transit backend so
  production deployments can keep OIDC private signing material outside SatOIDC.
- Include Testcontainers-backed OpenBao integration coverage for the real
  Transit path.

### 3. Extract Persistence-Heavy UI Actions Into Services

Status: draft.

Spec:

- `specs/features/route-service-extraction/spec.md`

Expected outcome:

- Move account, wallet, client-management, and permission-request mutations out
  of NiceGUI route closures into focused service helpers with unit coverage.

### 4. Add Lightweight Load/Concurrency Checks For Token Issuance

Status: backlog.

Specs:

- `specs/contracts/authlib-adapter.md`
- `specs/flows/token-lifecycle.md`

Expected outcome:

- Add a lightweight smoke benchmark for `/oauth/token` against PostgreSQL to
  establish a local latency/error/threadpool baseline.

### 5. Implement Email Verification And Account Recovery

Status: draft.

Spec:

- `specs/features/email-verification/spec.md`

Expected outcome:

- Implement verified-email state, single-use verification/recovery tokens,
  verified-email password reset, UI updates, and focused tests.
- Include Testcontainers-backed email-server integration coverage for SMTP
  delivery and captured verification/recovery messages.

### 6. Refactor Test Layer For Quality Specs

Status: in progress.

Specs:

- `specs/features/quality-testing/spec.md`
- `specs/features/quality-testing/pytest-extensions.md`
- `specs/features/quality-testing/hypothesis-property.md`
- `specs/features/quality-testing/tavern-api-security.md`
- `specs/features/quality-testing/playwright-ui.md`
- `specs/features/quality-testing/locust-load.md`
- `specs/features/quality-testing/testcontainers-integration.md`

Expected outcome:

- Implement the test markers, task commands, fixtures, dependencies, and test
  directory structure needed by the quality-testing specs.

Progress:

- Added pytest markers and taskipy commands for unit, property, API security,
  integration, e2e, load, and non-load suites.
- Added bounded Hypothesis property tests for redirect safety and validators.
- Added API security smoke coverage for public route lookalikes.
- Added a selectable integration marker smoke and a bounded Locust public-route
  smoke scenario.

Remaining:

- Add Tavern YAML coverage for API security contracts.
- Extend load smoke coverage to seeded token issuance once PostgreSQL setup
  helpers exist.
