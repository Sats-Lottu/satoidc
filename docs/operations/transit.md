# SatOIDC Transit Signing Operations

Updated: 2026-05-18

SatOIDC can sign OpenID Connect ID Tokens with either:

- `OIDC_SIGNING_BACKEND=database`: internal encrypted database-backed RSA
  private JWK storage.
- `OIDC_SIGNING_BACKEND=transit`: OpenBao or HashiCorp Vault-compatible Transit
  signing.

Use `database` for local development, tests, demos, and small deployments whose
threat model accepts encrypted signing keys in the SatOIDC database. Prefer
`transit` for hardened production when private signing material must stay
outside the application database and process.

Transit is not a silent failover mechanism. If `transit` is configured and
Transit is unavailable, token issuance fails closed.

## Required Settings

Current runtime settings use these environment variable names. Planned
`SATOIDC_*` aliases are documented in
[Runtime Configuration Contract](../../specs/contracts/runtime-config.md), but
are not accepted by the current settings loader yet.

| Setting | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_SIGNING_BACKEND` | optional | `database` | Must be `database` or `transit`. |
| `OIDC_TRANSIT_ADDR` | required for transit | empty | OpenBao/Vault base URL, for example `https://openbao.example.com`. |
| `OIDC_TRANSIT_TOKEN` | required for transit | empty | Token with narrow Transit permissions. Current runtime does not support `_FILE` for this variable. |
| `OIDC_TRANSIT_MOUNT` | optional for transit | `transit` | Transit mount path without leading slash. |
| `OIDC_TRANSIT_KEY_NAME` | optional for transit | `satoidc-id-token` | Transit key used for OIDC ID Token signing. |
| `OAUTH2_JWT_ALG` | optional | `RS256` | Current Transit implementation expects RSA 2048 keys and RS256-compatible signing. |
| `OAUTH2_TOKEN_EXPIRES_IN` | optional | `300` | ID/access token lifetime in seconds. |
| `OIDC_JWKS_CACHE_TTL_SECONDS` | optional | `300` | JWKS cache safety window used for signing-key retirement. |
| `OIDC_KEY_RETENTION_MARGIN_SECONDS` | optional | `900` | Extra retention margin for validating keys after rotation. |

Keep `OIDC_TRANSIT_TOKEN` in the deployment platform secret store. Do not commit
it to the repository or bake it into images.

## OpenBao Setup

The current integration coverage uses OpenBao `openbao/openbao:2.5.2` with a
Transit mount. The same API shape is Vault-compatible.

Example operator setup, using the `bao` CLI:

```bash
export BAO_ADDR=https://openbao.example.com
export BAO_TOKEN=<operator-token>

bao secrets enable -path=transit transit
bao write -f transit/keys/satoidc-id-token type=rsa-2048
```

If the `transit` mount already exists, keep it and create only the key. SatOIDC
can also create the configured RSA key on first use when its token has the
required permissions.

Create a narrow policy for SatOIDC:

```hcl
path "transit/keys/satoidc-id-token" {
  capabilities = ["create", "read", "update"]
}

path "transit/keys/satoidc-id-token/rotate" {
  capabilities = ["update"]
}

path "transit/export/public-key/satoidc-id-token/*" {
  capabilities = ["read"]
}

path "transit/sign/satoidc-id-token/sha2-256" {
  capabilities = ["update"]
}
```

Issue an application token using the policy, then configure SatOIDC:

```env
OIDC_SIGNING_BACKEND=transit
OIDC_TRANSIT_ADDR=https://openbao.example.com
OIDC_TRANSIT_TOKEN=<satoidc-transit-token>
OIDC_TRANSIT_MOUNT=transit
OIDC_TRANSIT_KEY_NAME=satoidc-id-token
```

Use TLS between SatOIDC and OpenBao/Vault. Treat Transit unavailability as an
authentication outage because OIDC token issuance depends on signing.

## Startup And Key Behavior

When Transit mode is active, SatOIDC:

1. Selects the active signing-key metadata row from the database.
2. Ensures an RSA 2048 Transit key exists when a new key row is needed.
3. Exports the public key for JWKS publication.
4. Stores key metadata such as `kid` and backend reference in the database.
5. Sends JWT signing input to Transit for ID Token signatures.

Private signing material does not leave Transit. SatOIDC publishes only public
JWK data through `/.well-known/jwks.json`.

The `kid` for Transit keys is based on the Transit key name and version, for
example `satoidc-id-token-v1`. The backend reference stored in SatOIDC metadata
uses `transit:<key-name>:<version>`.

## Validation

After enabling Transit:

1. Confirm OpenBao/Vault health from the SatOIDC host:

   ```bash
   curl --fail --show-error "$OIDC_TRANSIT_ADDR/v1/sys/health"
   ```

2. Confirm the Transit key exists:

   ```bash
   curl --fail --show-error \
     --header "X-Vault-Token: $OIDC_TRANSIT_TOKEN" \
     "$OIDC_TRANSIT_ADDR/v1/$OIDC_TRANSIT_MOUNT/keys/$OIDC_TRANSIT_KEY_NAME"
   ```

3. Restart SatOIDC and inspect startup logs for signing readiness failures.
4. Fetch JWKS:

   ```bash
   curl --fail --show-error https://id.example.com/.well-known/jwks.json
   ```

5. Complete one authorization-code login from a real OIDC client and verify the
   ID Token signature against JWKS.

The integration suite verifies real OpenBao-backed signing:

```bash
cd satoidc
poetry run pytest tests/integration/test_openbao_transit_signing.py
```

This test requires Docker/Testcontainers availability.

## Failure Modes

| Failure | Behavior | Operator action |
| --- | --- | --- |
| `OIDC_SIGNING_BACKEND` is neither `database` nor `transit` | Settings validation fails at startup/import | Correct the value and restart. |
| `OIDC_SIGNING_BACKEND=transit` but address or token is missing | Signing readiness fails with `OIDC_TRANSIT_ADDR`/`OIDC_TRANSIT_TOKEN` error | Set both variables and restart. |
| OpenBao/Vault is unreachable or times out | Token issuance and signing-key readiness fail closed | Restore Transit reachability or switch backend only through a deliberate incident procedure. |
| Token lacks permissions | Transit requests fail with HTTP 403 | Update the policy/token and restart or retry the failed operation. |
| Transit key exists with the wrong type | SatOIDC rejects it because it must be `rsa-2048` | Create a new RSA key name and update `OIDC_TRANSIT_KEY_NAME`; do not reuse an incompatible key. |
| Public key export is disabled by policy | JWKS/key creation cannot complete | Grant read permission to `transit/export/public-key/<key>/*`. |
| Sign endpoint fails | OIDC token issuance fails | Check Transit logs, policy, key status, and network path. |
| Database metadata references a missing Transit key version | Signing fails for the active key | Restore the Transit key/version from backup or rotate/create a new signing key after assessing token validation impact. |

Do not configure automatic fallback from Transit to database signing in
production. Silent fallback changes the trust boundary and can produce tokens
with an unexpected key lineage.

## Fallback Procedure

Use this only during an incident when restoring Transit is slower than the
business recovery objective and the risk is accepted by the operator.

1. Declare the incident and record why Transit cannot be restored first.
2. Take a PostgreSQL backup before changing signing configuration.
3. Save the current JWKS output and the current `OIDC_SIGNING_BACKEND` value.
4. Change `OIDC_SIGNING_BACKEND=database` and ensure
   `OAUTH2_JWT_SECRET_KEY` is a strong non-placeholder secret.
5. Restart SatOIDC and fetch `/.well-known/jwks.json`.
6. Complete one OIDC login and verify the ID Token signature.
7. Notify relying-party operators if they pin keys or cache JWKS longer than
   the advertised cache window.
8. Plan a return to Transit and key rotation after the incident.

Database signing is less hardened because a combined compromise of database
contents and runtime secrets can compromise OIDC signing. Protect database
backups accordingly.

## Rotation Notes

SatOIDC keeps public keys for active and validating signing keys so older tokens
can validate during their lifetime and JWKS cache windows. The retention window
is based on:

```text
OAUTH2_TOKEN_EXPIRES_IN
+ OIDC_JWKS_CACHE_TTL_SECONDS
+ OIDC_KEY_RETENTION_MARGIN_SECONDS
```

Before rotating a Transit key, confirm Transit backups/snapshots are healthy.
After rotation, confirm JWKS contains the new active public key and any still
validating previous key until its retention window ends.
