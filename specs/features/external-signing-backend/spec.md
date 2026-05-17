# Spec: External OIDC Signing Backend

## Status

- Status: implemented
- Owner: TBD
- Created: 2026-05-16
- Updated: 2026-05-17
- Related code:
  - `satoidc/satoidc/auth/oidc_keys.py`
  - `satoidc/satoidc/auth/oauth2.py`
  - `satoidc/satoidc/routes/oauth2.py`
  - `satoidc/satoidc/models/`
- Related specs:
  - `specs/features/oidc-key-rotation/spec.md`
  - `specs/flows/token-lifecycle.md`
  - `specs/flows/deployment.md`

## Intent

Move OIDC signing toward a backend where private key material does not need to
be stored by SatOIDC, while keeping the current database-encrypted key store as
the local and MVP fallback.

SatOIDC must therefore support two operating modes:

- Internal signing, without OpenBao, using SatOIDC's own key lifecycle and
  encrypted database-backed private JWK storage.
- OpenBao-backed signing, using a Vault-compatible Transit backend for hardened
  deployments.

## Context

SatOIDC now persists RSA private JWKs encrypted in the database. This fixed
process-local key loss and multi-replica JWKS instability, but a compromise of
both database and runtime secrets can still compromise token signing.

The preferred hardened shape is a Vault-compatible Transit backend. OpenBao and
HashiCorp Vault expose compatible Transit concepts for signing operations, but
they differ in governance, licensing, managed-service maturity, and operating
model.

## Scope

In scope:

- Define a backend abstraction for OIDC signing.
- Support current encrypted database-backed signing as `database`.
- Add OpenBao support through a Vault-compatible Transit backend target as
  `transit`.
- Keep provider discovery and JWKS behavior unchanged for clients.
- Document operational requirements for OpenBao and HashiCorp Vault.

Out of scope:

- Replacing SQLAlchemy persistence for key metadata.
- Supporting every possible KMS/HSM provider in the first iteration.
- Making Transit mandatory for local development.
- Removing the internal signing mechanism.

## Rules

- SatOIDC must never expose private key material through HTTP responses, logs,
  audit events, or docs.
- `kid`, algorithm, key state, activation, validation, and retirement metadata
  remain in SatOIDC's database for OIDC lifecycle control.
- The Transit backend should sign with a stable key reference and version.
- The backend interface must be narrow enough to support both OpenBao and
  HashiCorp Vault without vendor-specific leakage into route handlers.
- If Transit is unavailable, production behavior must fail closed for token
  issuance rather than falling back silently to another key.
- SatOIDC must remain runnable without OpenBao.
- Deployments that use internal signing must surface the risk that compromise of
  both the database and runtime encryption secret compromises OIDC signing.

## Internal Signing Risk

Internal signing is acceptable for local development, tests, demos, and
deployments whose threat model accepts database-encrypted private key material.

It is not equivalent to OpenBao-backed signing:

- SatOIDC stores encrypted private JWK material in its own database.
- The runtime must decrypt that material to sign tokens.
- A combined compromise of the database and the runtime secret can expose the
  signing key and allow forged ID Tokens.
- Database backups become sensitive cryptographic assets and must be protected
  accordingly.
- Multiple operators or hosts with access to both database backups and runtime
  secrets increase the blast radius.

For hardened production, OpenBao-backed Transit signing is recommended because
private key material stays outside the SatOIDC database and application process.

## Backend Choice

Recommended default for SatOIDC and similar future self-hosted projects:

- Use a Vault-compatible Transit interface.
- Prefer OpenBao for self-hosted deployments aligned with open-source
  sovereignty and auditability.
- Keep compatibility with HashiCorp Vault for teams that need HCP/Enterprise
  support, commercial SLAs, or existing Vault operations.

Rationale:

- OpenBao keeps the project aligned with free/open-source governance and avoids
  baking a source-available vendor dependency into SatOIDC's production story.
- HashiCorp Vault remains the more conservative enterprise option when managed
  operations and vendor support matter more than licensing philosophy.
- A Vault-compatible adapter preserves optionality and makes the decision
  reversible.

## Flows

### Sign ID Token With Transit

1. SatOIDC selects the active signing key metadata row.
2. SatOIDC creates the JWT signing input.
3. SatOIDC sends the digest or payload to the Transit sign endpoint according
   to the selected algorithm contract.
4. SatOIDC receives the signature and assembles the JWT with the active `kid`.
5. SatOIDC audits the signing event without logging sensitive payload data.

### Sign ID Token Internally

1. SatOIDC selects the active signing key metadata row.
2. SatOIDC decrypts the encrypted private JWK using the configured runtime
   secret.
3. SatOIDC signs the JWT with the active `kid`.
4. SatOIDC audits the signing event without logging key material or token
   contents.

### Rotate Transit Key

1. An admin or job requests rotation.
2. SatOIDC creates or rotates a Transit key version.
3. SatOIDC records the backend reference and public JWK metadata.
4. SatOIDC activates the new key metadata and demotes the old key to
   `validating`.
5. JWKS continues publishing active and validating public keys until retirement.

## Contracts

- Configuration:
  - `OIDC_SIGNING_BACKEND=database|transit`
  - `OIDC_TRANSIT_ADDR`
  - `OIDC_TRANSIT_TOKEN` or workload-auth equivalent
  - `OIDC_TRANSIT_MOUNT`
  - `OIDC_TRANSIT_KEY_NAME`
- Database metadata:
  - `backend_reference`
  - `vault_key_name` or equivalent Transit key reference
  - `vault_key_version` or equivalent Transit key version
- OIDC output:
  - JWT `kid` remains stable.
  - JWKS remains standards-compatible.

## Implementation Notes

- The `database` signer is now selected through an OIDC signing backend
  boundary.
- `OIDC_SIGNING_BACKEND` validates `database` and `transit` as supported
  choices.
- `transit` uses the Vault-compatible Transit HTTP API with RSA 2048 keys,
  exported public keys, and `pkcs1v15` signatures through `/sign/:key/sha2-256`.
- Transit key versions are stored in `backend_reference` as
  `transit:<key-name>:<version>`.
- Token issuance signs through Transit without loading private key material into
  SatOIDC, and the integration suite verifies this path against OpenBao.

## Acceptance Criteria

- Given `OIDC_SIGNING_BACKEND=database`, when SatOIDC issues a token, then
  current encrypted database-backed behavior is preserved.
- Given OpenBao is not configured, when SatOIDC starts in development, then the
  app can still issue tokens through internal signing.
- Given `OIDC_SIGNING_BACKEND=transit`, when SatOIDC issues a token, then the
  private key never leaves the Transit backend.
- Given a deployment uses internal signing, when docs or health/config surfaces
  describe the deployment posture, then they warn that combined database and
  runtime-secret compromise can compromise OIDC signing.
- Given Transit is unavailable in production, when a token would be issued, then
  issuance fails closed and logs a structured operational error.
- Given a rotated Transit key, when old tokens remain valid, then the old public
  key remains in JWKS until its validation window ends.
- Given a relying party validates a token, then it does not need to know whether
  the token was signed by database or Transit backend.

## Test Plan

- Unit: backend interface selection, error handling, metadata mapping.
- Integration: fake Transit server or adapter stub for signing and rotation.
- Container integration: use Testcontainers to start OpenBao through Docker and
  verify real Vault-compatible Transit setup, signing, rotation, failure, and
  key-material isolation behavior.
- Security/regression: assert private key material is absent from logs, HTTP
  responses, and audit events.
- Manual/operations: documented OpenBao local compose setup before production
  rollout.

## Implementation Notes

Do not start by wiring a full secret manager through every part of the app.
Introduce a narrow signing backend boundary first, then add an OpenBao-backed
implementation. Keep HashiCorp Vault compatibility at the HTTP/API contract
layer.

Do not treat a fake Transit adapter as sufficient for the OpenBao integration
milestone. The production-facing backend needs at least one Testcontainers
integration test that boots OpenBao, enables Transit, creates or rotates a key,
and signs through the same client path used by SatOIDC.

## Traceability

- Code: `satoidc/satoidc/auth/oidc_keys.py`
- Tests: `satoidc/tests/test_oidc_key_rotation.py`
- Docs: `docs/priority-execution-backlog.md`
- Decisions: `agent-memory/decisions.md`
