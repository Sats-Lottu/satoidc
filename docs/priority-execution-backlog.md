# Priority Execution Backlog

Updated: 2026-05-16

This backlog is a temporary queue for open execution work. Completed items must
be removed from this file and summarized in `docs/priority-execution-history.md`.

## Open Items

### 1. Refactor Application Setup Bootstrap

Status: draft.

Spec:

- `specs/features/application-setup/spec.md`

Expected outcome:

- Refactor setup so fresh deployments validate or generate every required
  runtime value before the main app starts, including safe secret/token
  generation, root-user bootstrap, database readiness, OIDC signing readiness,
  and actionable messages for values that must remain managed by Coolify or the
  process environment.

### 2. Add OpenBao-Compatible External Signing Backend

Status: draft.

Spec:

- `specs/features/external-signing-backend/spec.md`

Expected outcome:

- Add a signing backend interface and a Vault-compatible Transit backend so
  production deployments can keep OIDC private signing material outside SatOIDC.

### 3. Validate SQLite And PostgreSQL Support Matrix

Status: backlog.

Specs:

- `specs/contracts/database.md`
- `specs/contracts/runtime-config.md`
- `specs/flows/deployment.md`

Expected outcome:

- Document and verify the SQLite/PostgreSQL support matrix, including migration
  compatibility and async/sync database URL consistency.

### 4. Extract Persistence-Heavy UI Actions Into Services

Status: draft.

Spec:

- `specs/features/route-service-extraction/spec.md`

Expected outcome:

- Move account, wallet, client-management, and permission-request mutations out
  of NiceGUI route closures into focused service helpers with unit coverage.

### 5. Add Operational Observability Baseline

Status: draft.

Spec:

- `specs/features/operational-observability/spec.md`

Expected outcome:

- Add sanitized standard-library logging for important auth, authorization,
  OIDC, LNURL, and mutation failures.

### 6. Add Lightweight Load/Concurrency Checks For Token Issuance

Status: backlog.

Specs:

- `specs/contracts/authlib-adapter.md`
- `specs/flows/token-lifecycle.md`

Expected outcome:

- Add a lightweight smoke benchmark for `/oauth/token` against PostgreSQL to
  establish a local latency/error/threadpool baseline.

### 7. Remove LNURL Schema Compatibility Shim When Safe

Status: backlog.

Reference:

- `docs/changes-2026-05-08.md`

Expected outcome:

- Confirm no imports depend on `satoidc/satoidc/auth/lnurl_schemas.py`, then
  remove the compatibility re-export.

### 8. Normalize Or Archive `relatorio.md`

Status: backlog.

Expected outcome:

- Fix the encoding and link it as an analysis artifact, or archive/remove it
  after actionable tasks are tracked elsewhere.

### 9. Implement Email Verification And Account Recovery

Status: draft.

Spec:

- `specs/features/email-verification/spec.md`

Expected outcome:

- Implement verified-email state, single-use verification/recovery tokens,
  verified-email password reset, UI updates, and focused tests.

### 10. Refactor Test Layer For Quality Specs

Status: draft.

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
