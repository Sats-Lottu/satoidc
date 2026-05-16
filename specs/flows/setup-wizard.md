# Setup Wizard Flow

Status: draft
Area: Bootstrap/Auth/UI
Last Updated: 2026-05-16

## Intent

Describe the current first-root-user setup flow used by local and container
deployments.

## Entry Point

`python -m setup_wizard` runs `satoidc/setup_wizard/__main__.py`.

Startup behavior:

1. `exists_root_user()` checks whether any `Permission` row has
   `permission_type == root`.
2. The wizard starts a NiceGUI app on port 8000.
3. If no root permission exists, the wizard shows the initial root creation
   flow.
4. If a root permission exists, the wizard requires root credentials before
   showing setup/reconfiguration checks. Root access may use login/email plus
   password credentials, or LNURL-auth with a Lightning wallet linked to a root
   account.
5. The wizard includes the setup route and LNURL callback route.

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

1. `poetry run alembic upgrade head`
2. `poetry run python -m setup_wizard`
3. `poetry run fastapi run --host 0.0.0.0 --port 8000 satoidc`

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

- Setup is limited to root-user creation and does not yet cover all runtime
  values needed to start the main application safely.
- Missing or placeholder production secrets are rejected by runtime settings,
  but there is no unified bootstrap flow to generate safe owned secrets or
  guide operators through platform-managed values.
- The setup wizard uses older visual styling than the main NiceGUI app.
- The setup wizard creates `nickname=None` when the optional nickname is empty,
  while the model expects a non-null nickname.
- The wizard and main app share port 8000 during container startup.

Related feature spec: `specs/features/application-setup/spec.md`.

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
