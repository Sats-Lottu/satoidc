# Phase 3: Setup Configuration And Bootstrap

Status: open
Priority: P1/P2
Recommended agents: backend configuration, security, database

## Task 3.1: Implement `VAR` And `VAR_FILE` Secret Resolution

1. Clear task name: Implement direct env and `_FILE` secret resolution.
2. Technical objective: support Docker/Coolify mounted secrets safely.
3. Detailed scope: direct value wins over file value; file values are UTF-8 and
   stripped of trailing newlines; missing or empty files fail clearly; secrets
   are masked in logs and review data.
4. Required inputs: `specs/features/setup-wizard/spec.md`,
   `specs/contracts/runtime-config.md`, `satoidc/satoidc/settings.py`.
5. Expected outputs: resolver helper and tests.
6. Dependencies: runtime namespace contract.
7. Completion criteria: all sensitive setup variables support `_FILE` where the
   spec requires it.
8. Validation/test criteria: unit tests for precedence, missing file, empty
   file, masking, and no log leakage.
9. Recommended specialized agent: backend config/security agent.
10. Priority: P1.
11. Estimated complexity: M.
12. Technical risks: leaking secrets or silently accepting empty secrets.
13. Potentially affected files/components: `settings.py`, `runtime_config.py`,
    `tests/test_settings.py`.
14. Contracts/interfaces involved: Runtime Configuration Contract, Setup Wizard
    spec.
15. Integration notes: setup UI and non-interactive bootstrap must reuse this
    resolver.

### Subtasks

- Define supported `_FILE` variables.
- Implement resolver.
- Implement masking helper.
- Add tests for all error cases.

## Task 3.2: Centralize Runtime Validation

1. Clear task name: Centralize issuer, public URL, secret, and database
   validation.
2. Technical objective: fail early for unsafe production runtime settings.
3. Detailed scope: HTTPS production URLs, issuer without query/fragment,
   strong app secrets, async/sync database URL compatibility, local issuer
   rejection in production.
4. Required inputs: `settings.py`, `validators.py`,
   `specs/contracts/runtime-config.md`.
5. Expected outputs: central validators and focused tests.
6. Dependencies: Task 3.1 recommended.
7. Completion criteria: production rejects unsafe or mismatched configuration
   before app startup proceeds.
8. Validation/test criteria: `test_settings.py` covers development and
   production cases.
9. Recommended specialized agent: backend validation agent.
10. Priority: P1.
11. Estimated complexity: S/M.
12. Technical risks: making development defaults fail accidentally.
13. Potentially affected files/components: `settings.py`, `validators.py`,
    tests.
14. Contracts/interfaces involved: Runtime Configuration Contract, Database
    Contract.
15. Integration notes: setup wizard should call the same validators.

### Subtasks

- Add issuer/public URL validation.
- Add production HTTPS checks.
- Add database URL compatibility checks if gaps remain.
- Add regression tests.

## Task 3.3: Add Persistent Setup State Model

1. Clear task name: Add setup state persistence.
2. Technical objective: store canonical setup state in the database.
3. Detailed scope: model/table with state, version, timestamps, completed actor,
   config hash, and last error.
4. Required inputs: Setup Wizard spec, `models/database.py`, Alembic.
5. Expected outputs: SQLAlchemy model and Alembic migration.
6. Dependencies: Task 3.2.
7. Completion criteria: setup state can be loaded and persisted on SQLite and
   PostgreSQL.
8. Validation/test criteria: model tests and migration tests; generate
   migration with Alembic autogenerate.
9. Recommended specialized agent: backend database/migration agent.
10. Priority: P1.
11. Estimated complexity: M.
12. Technical risks: migration drift or hand-written migration mistakes.
13. Potentially affected files/components: `models/database.py`,
    `migrations/versions/`, tests.
14. Contracts/interfaces involved: Database Contract, Setup Wizard spec.
15. Integration notes: required before interactive wizard and setup lock.

### Subtasks

- Add model.
- Generate migration with autogenerate.
- Review constraints and indexes.
- Add SQLite/PostgreSQL compatible tests.

## Task 3.4: Implement Non-Interactive Root Bootstrap

1. Clear task name: Implement root user bootstrap from environment.
2. Technical objective: allow headless deployments to create the first root
   account without public interactive setup.
3. Detailed scope: read admin username, email, and password; support password
   via `_FILE`; create root only when no root/admin exists; audit result.
4. Required inputs: `setup_wizard/`, `auth/security.py`, `models/`,
   setup tests.
5. Expected outputs: idempotent bootstrap path and tests.
6. Dependencies: Tasks 3.1 and 3.3.
7. Completion criteria: bootstrap creates the first root once and never
   recreates or overwrites an existing root/admin.
8. Validation/test criteria: setup tests for first run, existing admin, missing
   env vars, weak password, and `_FILE`.
9. Recommended specialized agent: backend auth/bootstrap agent.
10. Priority: P1.
11. Estimated complexity: M.
12. Technical risks: account takeover through accidental root recreation.
13. Potentially affected files/components: `setup_wizard/`, `models/`,
    `tests/setup/`.
14. Contracts/interfaces involved: Security And Session Contract, Setup Wizard
    spec.
15. Integration notes: needed before production non-interactive deployments.

### Subtasks

- Resolve admin env vars.
- Check for existing root/admin.
- Hash password using existing password mechanism.
- Persist root permission.
- Add audit/log events and tests.

## Task 3.5: Add Setup Concurrency Lock

1. Clear task name: Add setup execution lock.
2. Technical objective: prevent concurrent setup sessions from applying
   conflicting configuration.
3. Detailed scope: database-backed lock or equivalent transactional guard,
   recoverable failed state, and clear locked diagnostics.
4. Required inputs: setup state model and setup wizard spec.
5. Expected outputs: lock helper and concurrency tests.
6. Dependencies: Task 3.3.
7. Completion criteria: concurrent setup attempts cannot both apply.
8. Validation/test criteria: tests simulate two setup attempts and verify one
   fails with a controlled state.
9. Recommended specialized agent: backend concurrency/database agent.
10. Priority: P2.
11. Estimated complexity: M.
12. Technical risks: stuck lock or database-specific behavior.
13. Potentially affected files/components: `setup_wizard/`, `models/`, tests.
14. Contracts/interfaces involved: Database Contract, Setup Wizard spec.
15. Integration notes: required before exposing interactive setup.

### Subtasks

- Define lock state transitions.
- Implement acquire/release/fail behavior.
- Add stale lock handling if needed.
- Add concurrency tests.

