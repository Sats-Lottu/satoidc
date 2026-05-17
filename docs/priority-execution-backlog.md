# Priority Execution Backlog

Updated: 2026-05-17

This backlog is a temporary queue for open execution work. Completed items must
be removed from this file and summarized in `docs/priority-execution-history.md`.

## Open Items

### 1. Add OpenBao-Compatible External Signing Backend

Status: draft.

Spec:

- `specs/features/external-signing-backend/spec.md`

Expected outcome:

- Add a signing backend interface and a Vault-compatible Transit backend so
  production deployments can keep OIDC private signing material outside SatOIDC.
- Include Testcontainers-backed OpenBao integration coverage for the real
  Transit path.

### 2. Extract Persistence-Heavy UI Actions Into Services

Status: draft.

Spec:

- `specs/features/route-service-extraction/spec.md`

Expected outcome:

- Move account, wallet, client-management, and permission-request mutations out
  of NiceGUI route closures into focused service helpers with unit coverage.

### 3. Implement Email Verification And Account Recovery

Status: draft.

Spec:

- `specs/features/email-verification/spec.md`

Expected outcome:

- Implement verified-email state, single-use verification/recovery tokens,
  verified-email password reset, UI updates, and focused tests.
- Include Testcontainers-backed email-server integration coverage for SMTP
  delivery and captured verification/recovery messages.

