# Spec: LNURL Registration Valid User Creation

## Status

- Status: implemented
- Owner: TBD
- Created: 2026-05-18
- Updated: 2026-05-18
- Product source:
  - `prd.md`
  - `relatorio_tecnico.md`
- Related code:
  - `satoidc/satoidc/routes/lnurl_auth.py`
  - `satoidc/satoidc/models/__init__.py`
- Related specs:
  - `specs/flows/lnurl-auth.md`
  - `specs/contracts/database.md`
  - `specs/features/quality-testing/hypothesis-property.md`

## Intent

Prevent LNURL registration from creating an invalid `User` row. The current
route can instantiate `User(nickname=None)`, while the database contract defines
`nickname` as non-null with a default display value.

## Problem

LNURL registration is a public onboarding path. If it attempts to persist a user
with a null nickname, registration fails with an integrity error and the wallet
flow becomes unusable for new users.

## Scope

In scope:

- Ensure LNURL `register` creates users with the default nickname `satoshi`
  when no nickname is supplied.
- Preserve password registration behavior.
- Add focused regression coverage for LNURL registration user creation.
- Avoid leaking wallet public keys or generated identifiers in logs.

Out of scope:

- Reworking the meaning of LNURL `auth`.
- Requiring email, login, or password for LNURL-only users.
- Changing wallet link/relink behavior on the profile page.

## Requirements

- LNURL registration must never pass `nickname=None` to the `User` model.
- The default nickname for LNURL-created users is `satoshi`.
- The default nickname must satisfy the same validation assumptions used by the
  rest of the app.
- If the selected nickname collides with future uniqueness rules, the user
  creation helper must remain easy to adapt.
- Registration failures must be surfaced through existing LNURL event/error
  paths without exposing sensitive wallet material.

## Acceptance Criteria

- Given a valid LNURL `register` challenge and a new wallet key, when the wallet
  callback succeeds, then SatOIDC persists a `User` with `nickname="satoshi"`.
- Given the same wallet key registers again, when a user already exists, then the
  flow resolves or rejects consistently with the existing registration contract
  without creating duplicate users.
- Given the database enforces `nickname NOT NULL`, when LNURL registration runs,
  then no `IntegrityError` is raised for nickname.
- Given tests inspect the persisted user, then the nickname is exactly
  `satoshi`.

## Test Plan

- Unit or integration: valid LNURL register callback persists a user with
  `nickname="satoshi"`.
- Regression: callback path no longer contains a nullable nickname assignment.
- Security: invalid signature and consumed challenge behavior still fail closed.

## Implementation Notes

The implemented default is the literal nickname `satoshi`. Do not derive the
default nickname from full wallet public keys.
