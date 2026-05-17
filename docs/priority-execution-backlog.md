# Priority Execution Backlog

Updated: 2026-05-17

This backlog is a temporary queue for open execution work. Completed items must
be removed from this file and summarized in `docs/priority-execution-history.md`.

## Open Items

### 1. Implement Email Verification And Account Recovery

Status: draft.

Spec:

- `specs/features/email-verification/spec.md`

Expected outcome:

- Implement verified-email state, single-use verification/recovery tokens,
  verified-email password reset, UI updates, and focused tests.
- Include Testcontainers-backed email-server integration coverage for SMTP
  delivery and captured verification/recovery messages.

