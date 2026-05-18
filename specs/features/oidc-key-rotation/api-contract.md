# API Contract: OIDC Key Rotation

## Status

- Status: implemented
- Created: 2026-05-06
- Updated: 2026-05-18

## Lifecycle Note

This API contract is retained as implementation evidence for the implemented
OIDC key rotation feature. Current behavior should be checked against the code,
`spec.md`, and external signing follow-up work before extending the contract.

## Public Discovery

```http
GET /.well-known/openid-configuration
```

Response must include:

```json
{
  "issuer": "https://auth.example.com",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
}
```

`jwks_uri` must point to the canonical JWKS endpoint.

## Public JWKS

```http
GET /.well-known/jwks.json
```

Response:

```json
{
  "keys": [
    {
      "kid": "sat-oidc-2026-05-06-001",
      "alg": "RS256",
      "kty": "RSA",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

Rules:

- Include keys with status `active` or `validating`.
- Exclude keys with status `retired`.
- Exclude private fields, encrypted private material and backend references.
- Set cache headers according to configured JWKS cache TTL.

## JWT Header

Every JWT signed by SatOIDC must include:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "sat-oidc-2026-05-06-001"
}
```

`kid` must match a key currently published in JWKS for the full period in which the token may be valid.

## Admin: Create Key

```http
POST /admin/oidc/keys
```

Response:

```json
{
  "kid": "sat-oidc-2026-05-06-001",
  "alg": "RS256",
  "kty": "RSA",
  "use": "sig",
  "status": "validating",
  "created_at": "2026-05-06T10:30:00Z"
}
```

## Admin: Activate Key

```http
POST /admin/oidc/keys/{kid}/activate
```

Response:

```json
{
  "active_kid": "sat-oidc-2026-05-06-002",
  "previous_active_kid": "sat-oidc-2026-05-06-001",
  "previous_status": "validating",
  "retired_after": "2026-05-06T11:30:00Z"
}
```

## Admin: Rotate Key

```http
POST /admin/oidc/keys/rotate
```

Semantics:

- Create a new key.
- Publish it as `validating`.
- Activate it.
- Demote previous active key to `validating`.
- Return the same state summary as activation plus created key metadata.

## Admin: Retire Expired Keys

```http
POST /admin/oidc/keys/retire-expired
```

Response:

```json
{
  "retired": [
    {
      "kid": "sat-oidc-2026-05-06-001",
      "retired_at": "2026-05-06T11:31:00Z"
    }
  ]
}
```

## Admin: List Keys

```http
GET /admin/oidc/keys
```

Response:

```json
{
  "keys": [
    {
      "kid": "sat-oidc-2026-05-06-001",
      "alg": "RS256",
      "kty": "RSA",
      "use": "sig",
      "status": "validating",
      "created_at": "2026-05-06T10:30:00Z",
      "activated_at": "2026-05-06T10:45:00Z",
      "validating_since": "2026-05-06T11:00:00Z",
      "retired_after": "2026-05-06T12:00:00Z",
      "retired_at": null,
      "backend_reference": "vault:transit/satoidc/1"
    }
  ]
}
```

Rules:

- Requires administrative authorization.
- Must not return private key material.
- May return backend references only if they do not expose sensitive values.

## Audit Events

Minimum event shape:

```json
{
  "event": "key.activated",
  "kid": "sat-oidc-2026-05-06-001",
  "actor": "system",
  "occurred_at": "2026-05-06T10:30:00Z"
}
```

Required events:

- `key.created`
- `key.activated`
- `key.demoted_to_validating`
- `key.retired`
- `token.signed`
