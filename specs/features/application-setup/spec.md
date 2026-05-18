# Application Setup Bootstrap

## Status

- Status: superseded
- Owner: TBD
- Created: 2026-05-16
- Updated: 2026-05-18
- Superseded by: `specs/features/setup-wizard/spec.md`
- Decision: `specs/decisions/2026-05-18-setup-wizard-spec-consolidation.md`
- Related code:
  - `satoidc/entrypoint.sh`
  - `satoidc/setup_wizard/`
  - `satoidc/satoidc/settings.py`
  - `compose.yaml`

## Summary

This spec captured the first setup-bootstrap hardening slice: startup
configuration validation, root-user bootstrap, generated-owned secret handling,
database readiness, and OIDC signing readiness.

That work was implemented and remains part of the product history, but this file
is no longer the canonical source for future Setup Wizard behavior.

## Supersession Rationale

The later Setup Wizard product requirement expanded beyond this narrow bootstrap
slice. It now covers:

- guided first-install configuration;
- non-interactive env-var bootstrap;
- `_FILE` secret support;
- setup state persisted in the database;
- reconfiguration by authenticated admins;
- env-var precedence and read-only UI fields;
- admin creation strategy;
- SMTP, database, OIDC, JWK, LNURL, and initial-client setup;
- full wizard state machine and acceptance criteria.

Keeping both specs active would duplicate requirements and make implementation
planning ambiguous. Future setup work must use
`specs/features/setup-wizard/spec.md` as the canonical feature spec.

## Historical Scope Preserved

The following implemented concerns remain valid and are incorporated into the
complete Setup Wizard spec:

- Production startup must reject placeholder secrets.
- Setup must not overwrite existing non-placeholder secrets.
- OIDC issuer/public URL values are operator-owned.
- Database URLs must be validated before app startup.
- Root-user bootstrap must complete before normal app startup.
- Generated secrets must not be printed to logs.
- Coolify/platform-managed values should remain managed by the platform.

## Traceability

- Canonical spec: `specs/features/setup-wizard/spec.md`
- Current flow description: `specs/flows/setup-wizard.md`
- Runtime contract: `specs/contracts/runtime-config.md`
- Deployment flow: `specs/flows/deployment.md`
