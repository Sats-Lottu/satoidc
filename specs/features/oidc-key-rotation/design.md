# Design: OIDC Key Rotation

## Status

- Status: implemented
- Created: 2026-05-06
- Updated: 2026-05-18

## Lifecycle Note

This design document is a historical implementation design for the OIDC key
rotation feature. The feature has been implemented and the canonical behavior is
tracked in `spec.md`, `api-contract.md`, `tasks.md`, and the current code.

The original design identified Vault Transit as the preferred hardened backend.
The project later implemented the broader OpenBao/Vault-compatible Transit
backend in `specs/features/external-signing-backend/spec.md`.

## Previous Behavior

Before implementation, SatOIDC used an in-memory RSA key generated during
startup. This created three production risks:

- restart invalidated the previous public key;
- replicas could sign tokens with different keys;
- key lifecycle, audit, and stable `kid` handling were missing.

## Components

- `OidcSigningKey`: persisted key metadata and encrypted/private backend
  reference.
- `OidcSigningKeyRepository`: queries and transitions key state transactionally.
- `OidcSigningService`: signs JWTs using the active key and records
  `token.signed`.
- `OidcKeyRotationService`: generates, activates, demotes, and retires keys.
- JWKS publisher: serializes public key material only.
- Admin endpoints: expose manual key lifecycle operations to authorized admins.

## Storage Options

### Internal Database Fallback

The MVP stores encrypted private JWK material in the database. This mode is
sufficient for development, tests, demos, and simple deployments that accept the
documented risk.

Rules:

- private material is encrypted before persistence;
- the encryption secret does not live in the same database row;
- logs and errors mask private material;
- decrypted material exists only for the minimum signing scope.

### Transit Backend

Hardened production should use OpenBao/Vault-compatible Transit signing. In
that mode, SatOIDC stores backend references and public metadata, and the
Transit backend performs signing.

## State Transitions

Allowed transitions:

- `validating` -> `active`
- `active` -> `validating`
- `validating` -> `retired`

Rules:

- only one key may be `active`;
- activation happens in a single transaction;
- activating a new key demotes the previous active key to `validating` and sets
  its retirement deadline;
- retired keys are never promoted again.

## Signing Flow

The token issuer resolves the active key at signing time. It must not depend on
process restart or module-level key state.

If no active key exists, token issuance fails safely. If signing fails, the
error is logged without sensitive material and returned as the appropriate
OAuth/OIDC error.

## JWKS Flow

`/.well-known/jwks.json` returns only keys in `active` or `validating` state.

Published keys contain public parameters only:

```json
{
  "kid": "sat-oidc-2026-05-06-001",
  "alg": "RS256",
  "kty": "RSA",
  "use": "sig",
  "n": "...",
  "e": "AQAB"
}
```

`private_jwk_encrypted`, backend references, and administrative fields must not
leave the server.

## Retention

`retired_after` must account for:

- the longest token lifetime signed by the key;
- expected clock skew;
- JWKS/client cache TTL;
- a safety margin.

## Authorization And Audit

Manual endpoints require existing admin/root authorization. Manual operations
record the authenticated actor. Background jobs record `actor=system`.

## Discovery

OIDC discovery and JWKS live at:

- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`

OAuth endpoints can remain under `/oauth`, but discovery and JWKS must not
depend on the `/oauth` prefix.
