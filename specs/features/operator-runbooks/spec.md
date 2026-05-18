# Spec: Operator Runbooks

## Status

- Status: draft
- Owner: TBD
- Created: 2026-05-18
- Updated: 2026-05-18
- Product source:
  - `prd.md`
  - `relatorio_tecnico.md`
- Related docs:
  - `README.md`
  - `docs/deployment/vps.md`
  - `docs/database-support-matrix.md`
  - `docs/local-development-troubleshooting.md`
- Related specs:
  - `specs/flows/deployment.md`
  - `specs/contracts/runtime-config.md`
  - `specs/features/external-signing-backend/spec.md`

## Intent

Provide operator-facing documentation required for SatOIDC to be adopted as a
self-hosted product rather than only a developer-run application.

## Scope

In scope:

- Backup and restore for PostgreSQL and local SQLite.
- Upgrade procedure and migration failure handling.
- Reverse proxy and TLS setup.
- Forwarded headers and real client IP considerations.
- SMTP/email delivery configuration and troubleshooting.
- OpenBao/Vault Transit setup and failure modes.
- Health checks and basic incident response.
- Links from README and docs indexes.

Out of scope:

- Managed hosting documentation.
- Kubernetes Helm chart.
- Full disaster recovery automation.
- Vendor-specific monitoring setup beyond examples.

## Required Documents

- `docs/operations/runbook.md`
- `docs/operations/reverse-proxy.md`
- `docs/operations/email.md`
- `docs/operations/transit.md`
- Optional: `docs/operations/observability.md` if logging and metrics work lands
  in a separate implementation.

## Acceptance Criteria

- Given a new operator starts from README, then they can find deployment,
  backup, restore, upgrade, email, Transit, and reverse proxy docs without
  scanning the repository.
- Given PostgreSQL is used, then the runbook includes `pg_dump`/restore guidance
  and describes when to stop the app.
- Given SQLite is used locally, then the runbook points to local troubleshooting
  and warns about runtime database files.
- Given OpenBao/Vault Transit is configured, then the runbook identifies required
  environment variables and failure behavior.
- Given reverse proxy deployment is used, then the docs describe TLS, forwarded
  headers, and how they affect future rate limiting and audit logs.

## Test Plan

- Documentation review: all new docs are linked from `docs/README.md`.
- Manual validation: run through a backup and restore procedure in a disposable
  environment.
- Link check: no orphan Markdown files.
