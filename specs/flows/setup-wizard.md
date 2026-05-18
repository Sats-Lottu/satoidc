# Setup Wizard Flow

Status: draft
Area: Bootstrap/Auth/UI
Last Updated: 2026-05-18

## Intent

Describe the current first-root-user setup flow used by local and container
deployments.

Canonical future Setup Wizard requirements live in
`specs/features/setup-wizard/spec.md`. This flow document describes the current
runtime sequence and should not duplicate the complete feature requirements.

## Entry Point

`python -m setup_wizard` runs `satoidc/setup_wizard/__main__.py`.

Startup behavior:

1. Bootstrap validates runtime configuration and database connectivity.
2. Alembic migrations run.
3. `exists_root_user()` checks whether any `Permission` row has
   `permission_type == root`.
4. The wizard starts a NiceGUI app on port 8000.
5. If no root permission exists, the wizard shows the initial root creation
   flow.
6. If a root permission exists, the wizard requires root credentials before
   showing setup/reconfiguration checks. Root access may use login/email plus
   password credentials, or LNURL-auth with a Lightning wallet linked to a root
   account.
7. The wizard includes only setup-specific routes and the LNURL callback
   route. Unknown setup-wizard endpoints redirect to `/`.
8. Bootstrap validates database-backed root permission and OIDC signing-key
   readiness after the wizard exits.
9. Importing `satoidc` package modules must not mount the main application.
   The main application is exposed by `satoidc/main.py`.

## Reconfiguration Access

After a root permission exists, the wizard is still safe to run manually:

1. User opens `/` in the setup wizard.
2. The wizard requires an active root user.
3. User authenticates with login/email plus password or with LNURL-auth from a
   Lightning wallet linked to a root account.
4. The wizard shows service configuration checks and operator guidance.
5. The wizard does not offer first-root creation while a root permission exists.
6. Re-running the wizard must not rotate existing secrets or overwrite
   non-placeholder values unless an explicit future rotation flow is added.

## Runtime Configuration Flow

Configuration values are loaded through Pydantic settings in
`satoidc/settings.py`. The setup flow classifies each value as one of:

- Platform-managed: public deployment values such as `DOMAIN` and
  `OAUTH2_JWT_ISS`; the operator must set these in the environment or hosting
  platform.
- Generated-owned: internal secrets that SatOIDC may generate in a future
  approved setup step, then persist in `SETUP_GENERATED_SECRETS_PATH` when it
  points to an absolute shell env file path.
- Database-backed: values whose authoritative state lives in the database, such
  as root permissions and OIDC signing keys.

If required values are missing at deployment time, the current wizard reports
the failed bootstrap checks and keeps the operator in the setup flow. A future
implementation may persist generated-owned values in a setup-state file, but it
must not mutate platform-managed environment variables directly.

## Password Root Creation

1. User opens `/` in the setup wizard.
2. User enters login, email, optional nickname, password, and confirmation.
3. The wizard validates login, email, nickname, and password rules.
4. The wizard creates a `User`.
5. The wizard creates a `Permission` with `permission_type=root`.
6. The wizard commits both records.
7. The wizard notifies success and shuts down the NiceGUI app.

## LNURL Root Creation

1. User opens the QR action.
2. The wizard creates an LNURL `register` challenge.
3. Wallet calls `/auth/lnurl/callback`.
4. The LNURL callback creates or resolves a user for the wallet key.
5. The wizard receives the LNURL event.
6. The wizard creates a root permission for the returned user id.
7. The wizard commits the permission and shuts down.

## Container Integration

`satoidc/entrypoint.sh` runs:

1. `poetry run python -m setup_wizard.bootstrap`
2. Source `SETUP_GENERATED_SECRETS_PATH` when bootstrap generated it.
3. `poetry run alembic upgrade head`
4. `poetry run python -m setup_wizard`
5. `poetry run python -m setup_wizard.bootstrap --database-state`
6. `poetry run fastapi run --host 0.0.0.0 --port 8000 satoidc/main.py`

If the wizard starts, it blocks until root setup completes and the app shuts
down.

Operators and developers can also invoke the same wizard on demand:

```bash
poetry run task setup_wizard
```

After the first root user exists, on-demand access to the wizard is protected
by root credentials for an active user with a current root permission. Password
login accepts login/email plus password, and Lightning login accepts a linked
LNURL-auth wallet for a root account.

## Current Gaps

- The setup wizard uses older visual styling than the main NiceGUI app.
- LNURL root creation depends on the shared LNURL registration callback; new
  wallet-created users receive the default nickname `satoshi`.
- The wizard and main app share port 8000 during container startup.

Related feature specs:

- Canonical future spec: `specs/features/setup-wizard/spec.md`
- Historical bootstrap slice:
  `specs/features/application-setup/spec.md`

## Acceptance Criteria

- Given no root permission exists, when `python -m setup_wizard` runs, then the
  setup UI starts.
- Given a root permission exists, when `python -m setup_wizard` runs, then the
  setup UI starts and requires valid root credentials before exposing setup
  checks.
- Given a Lightning wallet is linked to a root account, when its LNURL login
  callback succeeds, then setup access is granted.
- Given a Lightning wallet is not linked to a root account, when its LNURL
  login callback succeeds, then setup access is rejected.
- Given valid password setup input, when submitted, then a root user and root
  permission are persisted.
- Given LNURL setup succeeds, when the callback event arrives, then a root
  permission is persisted for the wallet-created user.
