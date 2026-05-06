# Spec-Driven Development

This folder is the Spec-Driven Development workspace for SatOIDC.

Use it to make product intent, business rules, protocol constraints, acceptance criteria, and implementation decisions explicit before changing code. Specs should stay versioned with the code and evolve with every feature change.

Start from [index.md](index.md). Keep every active feature, flow, contract, or decision linked there to avoid orphan specs.

## Workflow

1. Create or update a feature spec in `features/` using [_template.md](_template.md).
2. Link related flows, contracts, and decisions when the change affects protocol behavior, APIs, persistence, security, or UI.
3. Review the spec before implementation.
4. Implement the smallest code change that satisfies the spec.
5. Add or update tests mapped to the spec acceptance criteria.
6. Update the spec if implementation or product intent changes.

## Maturity Target

Current target: **Spec-anchored**.

Specs and code coexist in the repository. Humans edit specs as the durable source of intent, while code and tests remain the executable implementation. Do not treat generated code as complete until a human reviews behavior, security, and tests.

## Folder Map

- `features/`: product or technical feature specifications. See [features/README.md](features/README.md).
- `flows/`: user, auth, OAuth2/OIDC, LNURL, and operational flows. See [flows/README.md](flows/README.md).
- `contracts/`: API, token, event, database, and integration contracts. See [contracts/README.md](contracts/README.md).
- `decisions/`: short SDD-level decisions that affect specs or implementation. See [decisions/README.md](decisions/README.md).
- `_template.md`: default template for new specs.

## Governance Rules

- A feature is not ready for implementation until its acceptance criteria are testable.
- Specs must mention security and privacy impact when auth, identity, redirect, token, keys, sessions, or user data are involved.
- Specs must identify affected code areas.
- Pull requests that change behavior should update the related spec or explicitly state why no spec update is needed.
- Avoid vague intent such as "improve auth"; describe observable behavior and failure cases.
