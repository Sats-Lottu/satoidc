# Tasks: OIDC Key Rotation

## Status

- Status: implemented
- Updated: 2026-05-18

## Implementation Tasks

1. [x] Add `OidcSigningKey` model and migration.
2. [x] Generate migration with Alembic autogenerate and adjust only where
   necessary.
3. [x] Add encrypted private JWK persistence for the MVP fallback backend.
4. [x] Implement key repository with active-key lookup and publishable-key
   listing.
5. [x] Implement key rotation service:
   - generate key;
   - demote previous active key to `validating`;
   - activate new key.
6. [x] Replace in-memory RSA key usage with dynamic active-key resolution.
7. [x] Add `kid` to issued JWT headers.
8. [x] Publish `/.well-known/jwks.json` with only `active` and `validating`
   keys.
9. [x] Add `jwks_uri` to OIDC discovery.
10. [x] Add admin/root protected endpoints for manual key lifecycle operations.
11. [x] Add audit events for key lifecycle operations.
12. [x] Implement expired-key retirement.
13. [x] Add unit tests for key state transitions.
14. [x] Add token/JWKS integration tests.

## Implementation Order

1. Model and migration.
2. Key and JWKS services without changing token issuance.
3. Token issuance integration with the active key.
4. Admin endpoints and audit.
5. Tests and documentation.

## Historical Notes

- The MVP began with database-backed encrypted private keys.
- Hardened production signing later moved into the external signing backend
  spec and implementation.
