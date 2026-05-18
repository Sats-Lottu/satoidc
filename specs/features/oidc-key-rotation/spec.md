# Spec: OIDC Key Rotation

## Status

- Status: implemented
- Owner: TBD
- Created: 2026-05-06
- Updated: 2026-05-18
- Related code:
  - `satoidc/satoidc/auth/oauth2.py`
  - `satoidc/satoidc/routes/oauth2.py`
  - `satoidc/satoidc/models/`
  - `satoidc/migrations/`
- Related specs:
  - [OIDC Contract](../../contracts/oidc.md)
  - [Design](design.md)
  - [API Contract](api-contract.md)
  - [Test Plan](test-plan.md)
  - [Tasks](tasks.md)

## Intent

Implement secure generation, activation, rotation, publication, and retirement
of OIDC signing keys so JWTs issued by SatOIDC can be validated by clients
through the public JWKS endpoint.

Main rule: never remove a public key from JWKS while any still-valid token may
have been signed by that key.

## Context

Before this feature, SatOIDC signed OIDC tokens with an RSA key generated in
memory during application startup. That behavior made older tokens potentially
invalid after restart and prevented consistent multi-replica operation.

The implemented feature replaced that behavior with persistent key lifecycle
management, controlled JWKS publication, mandatory `kid` headers in JWTs, and
audit hooks for critical operations.

## Scope

In scope:

- generate asymmetric OIDC signing keys;
- maintain exactly one active signing key;
- publish `active` and `validating` public keys in JWKS;
- include `kid` in every issued JWT header;
- retain old public keys while tokens signed by them may still be valid;
- remove expired keys from JWKS safely;
- audit key creation, activation, demotion, retirement, and signing events;
- publish `jwks_uri` in OIDC discovery.

Out of scope:

- rotating OAuth client secrets;
- rotating refresh tokens;
- requiring a physical HSM.

## Architectural Decision

The preferred hardened production design uses OpenBao through a
Vault-compatible Transit interface as the cryptographic backend.

The implemented MVP stores the private key in the database encrypted with a key
derived from `OAUTH2_JWT_SECRET_KEY`. Private material is never exposed through
endpoints, logs, discovery documents, JWKS, or audit events.

SatOIDC must work with or without OpenBao. Without OpenBao, it uses internal key
lifecycle, encryption, and signing. With OpenBao, it requests signatures from
the Transit backend and keeps private key material outside the database and
application process.

The internal mode has a material risk: if an attacker obtains both the database
and the runtime secret used to encrypt private keys, they can compromise the
OIDC signing key and forge tokens. This mode is suitable for development,
tests, demos, and simple deployments that explicitly accept that risk. Hardened
production should prefer OpenBao Transit or an equivalent external backend.

## Key States

Each signing key has exactly one state:

- `active`: key used to sign new tokens.
- `validating`: old key still published in JWKS for token validation.
- `retired`: key removed from JWKS and not used for signing.

At any time there must be at most one `active` key. In normal operation there
must be exactly one `active` key before tokens can be issued.

## Functional Requirements

### RF01 - Generate Signing Key

SatOIDC must create a new asymmetric signing key with:

- `kid`
- `alg`
- `kty`
- `use`
- `created_at`
- `status`
- `public_jwk`
- `backend_reference`

New keys start in `validating` until activated.

### RF02 - Activate Key

SatOIDC must allow a newly created or idle key to become active. Activating a
new key must:

- demote the previous `active` key to `validating`;
- promote the new key to `active`;
- sign new tokens with the new `kid`;
- publish both old and new public keys while the old key remains in its
  validation window;
- happen in one transaction.

### RF03 - JWT Header

Every issued JWT must include:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sat-oidc-2026-05-06-001"
}
```

The `kid` must match a key published in JWKS for the full validity window of
the token.

### RF04 - JWKS Publication

SatOIDC must expose:

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`

JWKS must include only public keys with status `active` or `validating`.
`retired` keys and private material must never be returned.

### RF05 - Retire Old Keys

A `validating` key may become `retired` only after the maximum token lifetime
and configured safety window have passed. Retired keys are removed from JWKS
and never used for new signatures.

### RF06 - Audit

Every key rotation operation must write an audit event including actor, action,
`kid`, previous state, new state, timestamp, and result. Audit records must not
include private key material.

## Security Requirements

- Private key material must never appear in JWKS, logs, HTTP responses, audit
  events, trace spans, or error messages.
- Only authenticated users with administrative/root authorization can trigger
  manual key lifecycle endpoints.
- Concurrent activation must not produce two active keys.
- Startup must fail safely if token signing is requested without an active key.
- Internal encrypted database-backed keys are acceptable only as an MVP/fallback
  mode; hardened deployments should use Transit signing.

## Public Discovery

OIDC discovery must publish `jwks_uri`:

```json
{
  "issuer": "https://auth.example.com",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
}
```

## Use Cases

### UC01 - Issue Token

Given an `active` key exists, when SatOIDC issues an ID Token, then the token is
signed with the active key and includes the correct `kid` header.

### UC02 - Rotate Key

Given an `active` key exists, when a new key is activated, then the old key
moves to `validating`, the new key moves to `active`, and both public keys are
published in JWKS.

### UC03 - Retire Key

Given a `validating` key passed `retired_after`, when cleanup runs, then the key
moves to `retired` and is removed from JWKS.

## Acceptance Criteria

- AC01: Tokens include `kid`.
- AC02: JWKS publishes public keys only.
- AC03: JWKS publishes the active key and still-valid old keys.
- AC04: Private key material never appears in JWKS.
- AC05: Only one active key exists.
- AC06: Activating a key demotes the previous active key.
- AC07: The application does not need restart to use a newly active key.
- AC08: Old tokens remain verifiable until their validation window ends.
- AC09: Retired keys are not published or used for signing.
- AC10: Key lifecycle operations are audited.

## Tests

- Select exactly one active key.
- Prevent two active keys.
- Move the old active key to `validating`.
- Publish only `active` and `validating` keys in JWKS.
- Exclude private fields from JWKS.
- Sign tokens with the active key.
- Rotate keys without invalidating still-valid tokens.
- Retire old keys after the configured safety window.
- Reject unauthorized manual rotation.

## Configuration Examples

```env
OIDC_KEY_BACKEND=database
OIDC_KEY_ROTATION_ENABLED=true
OIDC_KEY_RETENTION_SECONDS=3600
```

```env
OIDC_KEY_BACKEND=transit
OIDC_TRANSIT_ADDR=https://openbao.example.com
OIDC_TRANSIT_KEY_NAME=satoidc-oidc-signing
OIDC_KEY_ROTATION_ENABLED=true
OIDC_KEY_RETENTION_SECONDS=3600
```
