# Decision: Consolidate Setup Wizard Specs

Date: 2026-05-18

## Context

SatOIDC had two overlapping setup specifications:

- `specs/features/application-setup/spec.md`, focused on the implemented
  bootstrap hardening slice.
- `specs/features/setup-wizard/spec.md`, a broader product and engineering
  specification for guided setup, non-interactive bootstrap, `_FILE` secrets,
  database-backed setup state, reconfiguration, and full wizard UX.

Keeping both active would duplicate requirements and create uncertainty about
which document governs future implementation.

## Decision

`specs/features/setup-wizard/spec.md` is the canonical feature spec for future
Setup Wizard work.

`specs/features/application-setup/spec.md` is retained as a superseded historical
record of the already implemented bootstrap slice.

`specs/flows/setup-wizard.md` remains a flow description of current behavior and
should link to the canonical feature spec for future behavior.

## Consequences

- New setup work must update `specs/features/setup-wizard/spec.md`.
- Existing bootstrap behavior remains valid but should be traced through the
  canonical Setup Wizard spec.
- Product requirements such as `_FILE` secrets, env-var precedence,
  database-backed setup state, and admin reconfiguration should not be copied
  into separate feature specs.
- If implementation splits into smaller PRs, those PRs may add task documents,
  but the canonical requirements remain in the complete Setup Wizard spec.

## Related Specs

- `specs/features/setup-wizard/spec.md`
- `specs/features/application-setup/spec.md`
- `specs/flows/setup-wizard.md`
- `specs/contracts/runtime-config.md`
