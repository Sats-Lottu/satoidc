# SDD Decisions

Use this folder for short decisions that govern specs and implementation.

Prefer a decision file when the choice affects multiple specs, protocol behavior, security posture, or long-term architecture.

Recommended filename format:

```text
YYYY-MM-DD-short-decision.md
```

Each decision should include context, decision, consequences, and links to related specs.

## Decisions

- [Setup Wizard Spec Consolidation](2026-05-18-setup-wizard-spec-consolidation.md):
  makes `features/setup-wizard/spec.md` the canonical setup spec and keeps
  `features/application-setup/spec.md` as a superseded historical record.
- [Repository Language Policy](2026-05-18-documentation-language-policy.md):
  requires English for all repository content while allowing AI-agent
  conversations in the user's preferred language.

Keep this list aligned with [../index.md](../index.md).
