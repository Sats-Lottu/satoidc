# Spec: Setup Wizard

## Status

- Status: review
- Owner: TBD
- Created: 2026-05-18
- Updated: 2026-05-18
- Related code:
  - `satoidc/setup_wizard/`
  - `satoidc/entrypoint.sh`
  - `satoidc/satoidc/settings.py`
  - `satoidc/satoidc/models/`
  - `satoidc/satoidc/auth/`
  - `satoidc/satoidc/routes/`
- Related specs:
  - `specs/features/application-setup/spec.md` (superseded historical slice)
  - `specs/flows/setup-wizard.md`
  - `specs/contracts/runtime-config.md`
  - `specs/contracts/database.md`
  - `specs/features/operator-runbooks/spec.md`
  - `specs/features/external-signing-backend/spec.md`

## 1. Overview

The SatOIDC Setup Wizard is the guided bootstrap and secure reconfiguration
flow for a self-hosted instance. It must allow a new deployment to become usable
without manually editing local files on first use, while remaining fully
automatable through environment variables, Docker, Coolify, and file-mounted
secrets.

The central rules are:

- every setting configurable by the wizard must also be configurable by
  environment variable;
- if all mandatory settings are present through environment variables or valid
  persisted state, the wizard is skipped automatically;
- if mandatory settings are missing in interactive mode, the wizard is shown;
- if mandatory settings are missing in non-interactive mode, startup fails with
  an explicit error;
- the database is the primary source for the durable setup-completed state.

Conceptual references:

- Twelve-Factor App: configuration lives in the environment, not in build
  artifacts or accidental local files.
- Keycloak bootstrap admin: deployments can create the first administrator
  non-interactively through environment variables.
- Docker secrets: sensitive values support both `VAR=value` and
  `VAR_FILE=/run/secrets/name`.
- Wizard UX pattern: small steps, clear progress, back/edit support, step-level
  validation, final review, and explicit apply.

## Canonicality

This is the canonical future Setup Wizard spec. The previous
`specs/features/application-setup/spec.md` remains only as a superseded
historical record for the already implemented bootstrap slice.

## 2. Goals

- Provide guided bootstrap for a fresh SatOIDC instance.
- Provide non-interactive bootstrap through environment variables.
- Create the initial root administrator through env vars or the wizard.
- Skip the wizard when the instance is already configured.
- Allow later reconfiguration only for authenticated administrators.
- Persist setup completion state in the database.
- Support sensitive values through direct env vars and `_FILE` env vars.
- Lock or mark read-only any UI field explicitly controlled by environment.
- Mask secrets in the UI, logs, final review, and audit records.
- Integrate setup with Alembic, Authlib/OIDC, JWK management, SMTP, LNURL Auth,
  and optional initial OIDC clients.
- Work predictably in Docker, Coolify, and local development.

## 3. Out Of Scope

- Implementing code in this spec.
- Writing directly to Coolify configuration through an API.
- Creating Helm charts or a Kubernetes operator.
- Replacing the normal SatOIDC admin dashboard.
- Rotating existing secrets without a dedicated rotation flow.
- Recreating the initial administrator when a root/admin already exists.
- Acting as a data migration tool.
- Implementing an internal WAF or in-app rate limiter when that responsibility
  is delegated to the reverse proxy.

## 4. Initialization Model

Startup must follow this conceptual order:

1. Load settings from all allowed sources.
2. Resolve direct secret values and `_FILE` secret values.
3. Validate the minimum database settings needed to connect.
4. Run Alembic to `head` if the deployment policy allows automatic migrations.
5. Load the durable setup state from the database.
6. Detect whether a root/admin user already exists.
7. Detect whether all mandatory settings are complete.
8. If everything is complete, skip the wizard and start the main application.
9. If settings are missing and the mode is interactive, show the wizard.
10. If settings are missing and the mode is non-interactive, fail startup with a
    clear error.

Pseudocode:

```python
resolved = resolve_config_sources(os.environ)
validate_database_config(resolved)
run_migrations_if_enabled(resolved)
setup_state = load_setup_state_from_database()

if can_skip_setup(resolved, setup_state):
    start_main_app()
elif resolved.setup_mode == "non_interactive":
    fail_startup(missing_requirements(resolved, setup_state))
else:
    start_setup_wizard(resolved, setup_state)
```

## 5. Rules For Skipping The Wizard

The wizard must be skipped when all conditions are true:

- the database is reachable;
- migrations are at `head`;
- the persisted setup state is `completed`;
- at least one user has `root` permission;
- all mandatory runtime settings are resolved from env vars or persisted state;
- no critical validation error exists for issuer, public base URL, secret key,
  JWK backend, database URL, or admin state.

It must also be skipped for non-interactive bootstrap when all mandatory env
vars are complete and the initial root user can be created safely.

## 6. Rules For Enabling The Wizard

The public setup wizard is enabled only when:

- setup state is `not_started`, `in_progress`, `failed`, or missing;
- mandatory configuration is incomplete;
- `SATOIDC_SETUP_MODE` allows interactive setup;
- no root/admin user exists yet, or an authenticated admin explicitly enters
  reconfiguration mode.

The public setup wizard is blocked when:

- setup state is `completed`;
- `SATOIDC_DISABLE_SETUP_AFTER_BOOTSTRAP=true`;
- a root/admin user already exists and the requester is not authenticated as an
  admin;
- another setup run holds the setup lock.

## 7. First Installation Flow

1. Operator starts SatOIDC with minimal deployment configuration.
2. Application resolves env vars and `_FILE` secrets.
3. Application runs migrations if allowed.
4. Application detects no completed setup state.
5. Wizard opens at the public setup route.
6. Operator completes validated steps.
7. Wizard shows a final masked review.
8. Operator applies configuration.
9. System persists non-secret configuration and setup state.
10. System creates the initial root user when no admin exists.
11. System optionally creates the initial OIDC client.
12. System writes audit records.
13. Wizard enters `completed`.
14. Public setup route becomes locked.
15. Operator is redirected to login/admin.

## 8. Reconfiguration Flow

Only authenticated administrators can enter reconfiguration mode. Reconfiguration
must never recreate the first administrator, reveal saved secrets, silently
overwrite env-controlled settings, or bypass audit logging.

The reconfiguration UI must show env-controlled fields as locked/read-only and
must require explicit confirmation for high-impact settings such as issuer,
public base URL, database URL, JWK backend, token lifetime, and SMTP transport.

## 9. Configuration Precedence

Configuration resolution order:

1. Direct environment variables.
2. `_FILE` environment variables.
3. Persisted database configuration.
4. Secure defaults.
5. Setup Wizard input.

Direct environment variables override everything else. `_FILE` variables are
used when the direct variable is absent and the value is sensitive. Persisted
database configuration is used for values that the wizard owns. Defaults are
allowed only when they are safe for the current environment. Wizard input is the
source of new persisted values, but it cannot override explicitly configured env
vars.

If both `VAR` and `VAR_FILE` are set, `VAR` wins and startup must log a
non-sensitive warning.

## 10. Supported Environment Variables

Mandatory settings:

| Variable | Required | `_FILE` | Secret | Purpose |
| --- | --- | --- | --- | --- |
| `SATOIDC_PUBLIC_BASE_URL` | yes | no | no | Public external base URL. |
| `SATOIDC_ISSUER` | yes | no | no | OIDC issuer URL. Must be HTTPS in production. |
| `SATOIDC_DATABASE_URL` | yes | yes | maybe | Async database URL. |
| `SATOIDC_SECRET_KEY` | yes | yes | yes | Application secret for sessions/crypto. |
| `SATOIDC_ADMIN_EMAIL` | yes for bootstrap | no | no | Initial admin email. |
| `SATOIDC_ADMIN_USERNAME` | yes for bootstrap | no | no | Initial admin username. |
| `SATOIDC_ADMIN_PASSWORD` | yes for bootstrap | yes | yes | Initial admin password. |
| `SATOIDC_SETUP_MODE` | yes | no | no | `interactive`, `non_interactive`, or `disabled`. |
| `SATOIDC_DISABLE_SETUP_AFTER_BOOTSTRAP` | yes | no | no | Disable public setup after completion. |

Optional settings:

| Variable | `_FILE` | Secret | Purpose |
| --- | --- | --- | --- |
| `SATOIDC_SMTP_HOST` | no | no | SMTP hostname. |
| `SATOIDC_SMTP_PORT` | no | no | SMTP port. |
| `SATOIDC_SMTP_USERNAME` | no | no | SMTP username. |
| `SATOIDC_SMTP_PASSWORD` | yes | yes | SMTP password. |
| `SATOIDC_SMTP_TLS` | no | no | Enable SMTP TLS. |
| `SATOIDC_SMTP_STARTTLS` | no | no | Enable STARTTLS. |
| `SATOIDC_EMAIL_SENDER` | no | no | Default sender address. |
| `SATOIDC_INSTANCE_NAME` | no | no | Human-readable instance name. |
| `SATOIDC_THEME` | no | no | UI theme preset. |
| `SATOIDC_LNURL_AUTH_ENABLED` | no | no | Enable LNURL Auth. |
| `SATOIDC_OIDC_DEFAULT_SCOPES` | no | no | Default OIDC scopes. |
| `SATOIDC_TOKEN_LIFETIME_SECONDS` | no | no | Access/ID token lifetime. |
| `SATOIDC_REFRESH_TOKEN_LIFETIME_SECONDS` | no | no | Refresh token lifetime. |
| `SATOIDC_REQUIRE_PKCE` | no | no | Require PKCE for public clients. |
| `SATOIDC_REDIRECT_URI_POLICY` | no | no | Redirect URI policy. |
| `SATOIDC_JWK_ROTATION_POLICY` | no | no | JWK rotation policy. |
| `SATOIDC_LOG_LEVEL` | no | no | Application log level. |
| `SATOIDC_BASIC_RATE_LIMIT` | no | no | Documentation-only basic limit when delegated to proxy. |

## 11. `_FILE` Secret Support

For every sensitive variable, SatOIDC must accept:

```text
SATOIDC_SECRET_KEY=value
SATOIDC_SECRET_KEY_FILE=/run/secrets/satoidc_secret_key
```

Rules:

- direct values take precedence over `_FILE`;
- file contents are read as UTF-8 and stripped of trailing line breaks;
- missing files fail with a clear error;
- empty files fail;
- resolved secret values are never logged;
- final review shows only masked values such as `********`;
- production docs recommend `_FILE` for passwords, tokens, and secrets.

## 12. Wizard Steps

Every step must declare its goal, fields, validations, error messages,
skippability, env-var compatibility, secret handling, and persistence target.

Minimum steps:

1. Welcome and initial diagnostics.
2. Instance configuration.
3. Database.
4. Security and keys.
5. Initial administrator.
6. Email/SMTP.
7. OIDC settings.
8. LNURL Auth.
9. Optional initial OIDC client.
10. Final review.
11. Apply configuration.
12. Completion.

## 13. Step Validations

### 13.1 Welcome And Initial Diagnostics

- Goal: show setup state, detected environment, database reachability,
  migration status, and locked env-controlled fields.
- Fields: none, diagnostics only.
- Validations: database can be checked; migrations are known; setup lock is
  available.
- Errors: database unreachable, migrations not at head, setup locked.
- Skippable: no.
- Env configurable: yes, diagnostics are derived.
- Secret: no.
- Persistence: setup state and audit event.

### 13.2 Instance Configuration

- Goal: configure public identity.
- Fields: instance name, public base URL, issuer, theme, log level.
- Validations: valid HTTPS URLs in production; issuer has no query/fragment;
  issuer is stable and matches OIDC discovery expectations.
- Errors: invalid URL, insecure production URL, issuer mismatch.
- Skippable: no.
- Env configurable: yes.
- Secret: no.
- Persistence: database configuration unless env-controlled.

### 13.3 Database

- Goal: confirm database configuration and migration readiness.
- Fields: database URL, migration mode, production SQLite override.
- Validations: URL parses; async and sync Alembic URLs are compatible; database
  is reachable; production does not use local SQLite unless explicitly allowed.
- Errors: invalid URL, unreachable database, migration mismatch, unsafe SQLite.
- Skippable: only if fully env-controlled.
- Env configurable: yes.
- Secret: yes when URL contains credentials.
- Persistence: metadata only; prefer environment for the URL.

### 13.4 Security And Keys

- Goal: configure application secret and signing key backend.
- Fields: app secret source, JWK backend, OpenBao/Vault address, key name,
  rotation policy.
- Validations: strong secret; backend reachable when configured; valid rotation
  policy; no private key appears in logs or UI.
- Errors: weak secret, missing backend settings, invalid key policy.
- Skippable: no.
- Env configurable: yes.
- Secret: yes.
- Persistence: non-secret metadata and backend references only.

### 13.5 Initial Administrator

- Goal: create the first root user if no admin exists.
- Fields: username, email, password, password confirmation.
- Validations: valid email, valid username, strong password, matching
  confirmation, no existing root/admin.
- Errors: invalid email, weak password, username conflict, admin already exists.
- Skippable: only when admin bootstrap env vars are complete or an admin exists.
- Env configurable: yes.
- Secret: password.
- Persistence: `User`, password hash, and root `Permission`.

### 13.6 Email/SMTP

- Goal: configure email delivery for verification and recovery.
- Fields: email mode, host, port, username, password, TLS, STARTTLS, sender.
- Validations: host/port required when SMTP is enabled; mutually coherent TLS
  settings; sender is a valid address; optional test delivery succeeds.
- Errors: invalid host, invalid sender, authentication failure, TLS failure.
- Skippable: yes if email features remain disabled.
- Env configurable: yes.
- Secret: SMTP password.
- Persistence: non-secret settings in database; password via env/_FILE.

### 13.7 OIDC Settings

- Goal: configure protocol defaults.
- Fields: scopes, token lifetime, refresh lifetime, PKCE requirement, redirect
  URI policy, consent defaults.
- Validations: lifetimes are positive and bounded; OIDC scopes are valid;
  redirect policy is not permissive in production.
- Errors: invalid scope, unsafe redirect policy, invalid lifetime.
- Skippable: yes with secure defaults.
- Env configurable: yes.
- Secret: no.
- Persistence: database configuration unless env-controlled.

### 13.8 LNURL Auth

- Goal: configure LNURL Auth support.
- Fields: enabled/disabled, callback public URL, default nickname policy.
- Validations: callback matches public base URL; LNURL-only registration creates
  a valid user with default nickname `satoshi` when no nickname is provided.
- Errors: callback mismatch, invalid URL, invalid default nickname policy.
- Skippable: yes if LNURL Auth is disabled.
- Env configurable: yes.
- Secret: no.
- Persistence: database configuration unless env-controlled.

### 13.9 Optional Initial OIDC Client

- Goal: optionally create the first relying-party client.
- Fields: client name, redirect URIs, grant types, response types, scopes,
  public/confidential mode.
- Validations: redirect URIs are absolute; localhost is allowed only in
  development; confidential clients receive a one-time secret display.
- Errors: invalid redirect URI, unsafe localhost in production, invalid grant.
- Skippable: yes.
- Env configurable: optional.
- Secret: generated client secret for confidential clients.
- Persistence: OAuth client models.

### 13.10 Final Review

- Goal: show exactly what will change before applying.
- Fields: read-only summary.
- Validations: all mandatory steps are valid; no unresolved critical warning.
- Errors: incomplete setup, locked state changed, concurrent update detected.
- Skippable: no.
- Env configurable: derived.
- Secret: all secrets masked.
- Persistence: none.

### 13.11 Apply Configuration

- Goal: execute setup atomically.
- Fields: confirmation.
- Validations: setup lock acquired; migrations at head; state still valid.
- Errors: lock conflict, database write failure, admin conflict, client conflict.
- Skippable: no.
- Env configurable: no.
- Secret: never displayed.
- Persistence: setup state, configuration, users, permissions, clients, audit.

### 13.12 Completion

- Goal: confirm setup completion and next steps.
- Fields: links to login/admin and operations docs.
- Validations: setup state is `completed`; public setup route is disabled when
  configured.
- Errors: post-apply verification failure.
- Skippable: no.
- Env configurable: no.
- Secret: no.
- Persistence: final audit event.

## 14. Persistence

The database is the primary source of setup state. A minimal model should store:

```json
{
  "state": "completed",
  "version": 1,
  "completed_at": "2026-05-18T00:00:00Z",
  "completed_by": "system-or-user-id",
  "config_hash": "sha256:...",
  "last_error": null
}
```

Non-secret wizard-owned values may be stored in a configuration table. Secrets
must not be stored in clear text. If a secret must be persisted, it requires a
dedicated encrypted secret store design and explicit audit coverage.

## 15. Security

Mandatory security requirements:

- hash the admin password with the project's current secure password mechanism;
- never log passwords, tokens, private JWKs, SMTP passwords, or client secrets;
- mask secrets in the final review and all subsequent UI views;
- protect against concurrent setup execution with a database-backed lock;
- apply CSRF protection when browser POST/stateful forms require it;
- rate-limit setup attempts at the reverse proxy or a documented edge layer;
- expose public setup only before completion;
- allow reconfiguration only for authenticated administrators;
- audit all setup and reconfiguration changes;
- lock fields controlled by environment variables;
- fail safely when critical configuration is absent or invalid.

## 16. Audit

Audit records must capture:

- setup started, failed, applied, completed, and locked events;
- actor (`system`, anonymous setup session, or authenticated admin);
- timestamp;
- source IP when available;
- changed non-secret fields;
- secret source type only (`env`, `_FILE`, generated, or masked), never value;
- old/new metadata for high-impact settings;
- failure reason without leaking sensitive values.

## 17. NiceGUI UX/UI

The wizard should use native NiceGUI/Quasar/Tailwind patterns:

- stepper/progress indicator for major steps;
- locked/read-only fields for env-controlled values;
- inline validation and clear error states;
- password fields with masked input and no post-save reveal;
- final review grouped by category;
- responsive desktop/mobile layout;
- no custom JavaScript unless explicitly approved;
- no nested cards or marketing-style landing page;
- controls should follow `DESIGN.md`.

## 18. Alembic Integration

- Setup must run only against the current migration head.
- Migration files must be generated with Alembic autogenerate before manual
  edits, following project policy.
- The wizard must never generate migrations.
- In Docker/Coolify, automatic migration execution is controlled by deployment
  policy.
- If migrations fail, setup enters `failed` with a recoverable diagnostic.

## 19. Authlib/OIDC Integration

The wizard must configure values used by OIDC discovery, issuer validation,
JWKS, token lifetimes, client defaults, scopes, and PKCE requirements. Authlib
database operations remain behind the current synchronous session boundary and
must be called from async routes through the project's threadpool helpers.

## 20. Initial Admin Strategy

Non-interactive bootstrap creates the initial root admin when all admin env vars
are present and no root/admin exists. Interactive setup collects the same data.

The wizard must never recreate the initial admin if any root/admin exists.
Attempted recreation must be denied and audited.

## 21. Email/SMTP Strategy

Email can be disabled for development or configured for production. SMTP secrets
should use `_FILE` in production. Invalid SMTP configuration must fail with
field-level messages and optional test-send diagnostics.

## 22. Database Strategy

`SATOIDC_DATABASE_URL` is mandatory. Production should prefer PostgreSQL.
SQLite is acceptable for local development, tests, demos, and explicitly
acknowledged simple deployments. Production with SQLite requires an explicit
override and warning. The wizard must not automatically migrate data from
SQLite to PostgreSQL.

## 23. Cryptographic Keys/JWK Strategy

The wizard must support the current internal key lifecycle and expose the
preferred hardened option: OpenBao/Vault-compatible Transit. Hardened production
should prefer Transit so private signing material remains outside the database
and application process.

## 24. LNURL Auth Strategy

The wizard controls whether LNURL Auth is enabled. LNURL registration must
create valid users; when no nickname is supplied, the default nickname is
`satoshi`. Callback URLs must be derived from and validated against the public
base URL.

## 25. Public URLs And OIDC Issuer Strategy

`SATOIDC_PUBLIC_BASE_URL` and `SATOIDC_ISSUER` must be absolute URLs. Production
requires HTTPS. The issuer should be stable because changing it can break
relying parties and tokens. Discovery must publish the configured issuer and
JWKS URI.

## 26. Initial OIDC Client Strategy

The wizard may optionally create one initial client to make first use easier.
Confidential clients get a generated secret shown once. Public clients should
require PKCE. Redirect URI validation must follow the configured policy.

## 27. Setup Wizard States

States:

- `not_started`: no durable setup progress exists.
- `in_progress`: wizard session is active and owns the setup lock.
- `ready_to_apply`: all required steps are valid.
- `applying`: configuration is being persisted.
- `completed`: setup is complete and public setup is disabled when configured.
- `failed`: setup failed with recoverable diagnostics.
- `locked`: another setup or deployment lock prevents changes.
- `reconfigure_mode`: authenticated admin is editing existing configuration.

Valid transitions:

- `not_started` -> `in_progress`
- `in_progress` -> `ready_to_apply`
- `ready_to_apply` -> `applying`
- `applying` -> `completed`
- `applying` -> `failed`
- `failed` -> `in_progress`
- `completed` -> `reconfigure_mode`
- `reconfigure_mode` -> `ready_to_apply`
- any mutable state -> `locked` when a lock conflict is detected

Invalid transitions:

- `completed` -> `not_started` without an explicit development reset;
- `completed` -> public setup;
- `reconfigure_mode` without an authenticated admin;
- `applying` -> `in_progress` without recording failure.

## 28. Error Cases

Errors must be actionable and specific:

- database unreachable;
- migration head mismatch;
- invalid issuer;
- insecure production URL;
- missing or weak secret;
- missing admin bootstrap fields in non-interactive mode;
- admin already exists;
- SMTP authentication/TLS failure;
- invalid redirect URI;
- unavailable JWK backend;
- missing `_FILE` secret file;
- empty secret file;
- concurrent setup lock;
- reverse proxy rate limiting not configured for production exposure.

## 29. Docker/Coolify Integration

In Docker/Coolify deployments:

- prefer env vars for non-secret settings;
- prefer `_FILE` for secrets when the platform supports mounted secrets;
- detect non-interactive deployments through `SATOIDC_SETUP_MODE`;
- allow automatic bootstrap when all mandatory env vars are present;
- fail explicitly when mandatory settings are incomplete in non-interactive
  mode;
- avoid depending on local SQLite for production unless explicitly accepted;
- allow a safe development reset path that clears setup state and local data only
  in development mode.

Example production secret mapping:

```yaml
services:
  satoidc:
    environment:
      SATOIDC_SETUP_MODE: non_interactive
      SATOIDC_SECRET_KEY_FILE: /run/secrets/satoidc_secret_key
      SATOIDC_ADMIN_PASSWORD_FILE: /run/secrets/satoidc_admin_password
    secrets:
      - satoidc_secret_key
      - satoidc_admin_password
```

## 30. Recommended Tests

Unit tests:

- config precedence resolution;
- `_FILE` secret resolution;
- secret masking;
- setup state transitions;
- admin bootstrap guard;
- issuer/public URL validation;
- SMTP validation;
- database URL validation.

Integration tests:

- wizard appears when setup is incomplete;
- wizard is skipped when mandatory env vars are complete;
- admin is created from env vars;
- admin is not recreated when one exists;
- env-controlled fields are locked;
- public setup is blocked after completion;
- reconfiguration requires authenticated admin;
- unavailable database produces recoverable diagnostics;
- concurrent setup is blocked.

E2E tests:

- first-run wizard flow;
- masked final review;
- invalid SMTP and invalid issuer messages;
- successful completion redirects to login/admin;
- mobile and desktop NiceGUI layouts.

## 31. Acceptance Criteria

- AC01: Fresh interactive deployment shows the wizard when mandatory settings
  are missing.
- AC02: Deployment with complete mandatory env vars skips the wizard.
- AC03: Non-interactive incomplete deployment fails with a clear error.
- AC04: Initial admin can be created by env vars or wizard.
- AC05: Existing admin is never recreated.
- AC06: Secrets are never displayed in clear text after entry.
- AC07: `_FILE` secrets work for all supported sensitive settings.
- AC08: Env-controlled fields are locked/read-only in the wizard.
- AC09: Setup completion state is persisted in the database.
- AC10: Public setup is unavailable after completion.
- AC11: Reconfiguration requires authenticated admin access.
- AC12: Audit records are written for setup and reconfiguration.
- AC13: OIDC discovery reflects configured issuer and public URLs.
- AC14: LNURL registration defaults missing nickname to `satoshi`.
- AC15: Docker/Coolify deployments can bootstrap without interactive access.
- AC16: Production docs include reverse-proxy rate-limit requirements.

## References

- [Twelve-Factor App: Config](https://12factor.net/config)
- [Keycloak bootstrap admin environment variables](https://www.keycloak.org/server/containers)
- [Docker secrets](https://docs.docker.com/engine/swarm/secrets/)
- [NiceGUI documentation](https://nicegui.io/documentation)
