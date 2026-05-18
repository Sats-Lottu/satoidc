# Test Plan: OIDC Key Rotation

## Status

- Status: implemented
- Created: 2026-05-06
- Updated: 2026-05-18

## Lifecycle Note

This test plan guided the implemented OIDC key rotation feature. It is retained
as implementation evidence and a regression reference. New external signing
coverage belongs to `specs/features/external-signing-backend/spec.md` and
`specs/features/quality-testing/testcontainers-integration.md`.

## Unit Tests

- Generate unique `kid` values for new keys.
- Create a new key with `status=validating`.
- Prevent two `active` keys at the same time.
- Select exactly one `active` key for signing.
- Move the previous active key to `validating` when another key is activated.
- Retire old keys only after the configured retention window.
- List only `active` and `validating` keys in JWKS.
- Hide `retired` keys from JWKS.
- Exclude private material from public JWK serialization.

## Integration Tests

### Token Signing

- Issue a token with the current active key.
- Assert the JWT header contains the active `kid`.
- Assert the public JWKS contains the matching key.

### Rotation

- Rotate a key and activate the new `kid`.
- Assert JWKS contains both the old and new keys during the validation window.
- Assert new tokens use the new `kid`.
- Assert old tokens remain verifiable while they are still valid.

### Retirement

- Freeze time beyond the retention window.
- Run the retirement job.
- Assert the old key no longer appears in JWKS.
- Assert retired keys are not used for new signatures.
- Assert the application uses the new key without restart.

## Endpoint Tests

- `GET /.well-known/openid-configuration` includes `jwks_uri`.
- `GET /.well-known/jwks.json` returns only public key material.
- `POST /admin/oidc/keys` creates a key for an authorized user.
- `POST /admin/oidc/keys/{kid}/activate` activates a key and demotes the
  previous one.
- `POST /admin/oidc/keys/retire-expired` retires expired keys.
- Unauthorized users cannot manage keys.

## Security Tests

- No response contains `private_jwk`, encrypted private material, or backend
  secrets.
- Logs do not include private material.
- Audit events include `kid`, action, actor, and result, but no private data.
- Concurrent activation cannot produce two active keys.
- Missing active key fails token issuance safely.
- Nonexistent or `retired` keys cannot be activated.

## Manual Smoke Test

1. Start SatOIDC.
2. Create and activate a new OIDC key.
3. Complete an authorization-code flow.
4. Decode the issued ID Token and inspect `kid`.
5. Fetch JWKS and confirm the `kid` is present.
6. Rotate the key.
7. Repeat token issuance and confirm the new `kid`.
8. Retire expired keys and confirm old keys disappear only after the safety
   window.
