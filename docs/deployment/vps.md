# VPS Deployment

Status: draft
Last Updated: 2026-05-16

This project deploys to a self-managed VPS through Coolify. GitHub Actions runs
quality gates first, then calls the Coolify deploy webhook.

## GitHub Actions

The repository defines two workflows:

- `.github/workflows/ci.yaml`: runs on `push` and `pull_request`, installs
  Python 3.11 and Poetry, runs Ruff, runs the non-e2e test suite, and checks
  that the SatOIDC Docker image builds.
- `.github/workflows/deploy-coolify.yaml`: runs after CI succeeds on `main`,
  or manually through `workflow_dispatch`, then calls the Coolify deploy
  webhook.

## Required GitHub Secrets

Configure these in GitHub under
`Settings -> Secrets and variables -> Actions`:

| Secret | Purpose |
| --- | --- |
| `COOLIFY_WEBHOOK` | Deploy webhook URL copied from the Coolify application. |
| `COOLIFY_TOKEN` | Coolify API token with deploy permission. |

## Coolify Preparation

The Coolify application should already be linked to this GitHub repository.
Configure it to use the `main` branch and this repository's Docker Compose
file.

To make GitHub Actions the deployment gate, disable automatic deploys in
Coolify and let `.github/workflows/deploy-coolify.yaml` call the deploy webhook
after CI passes.

In Coolify:

- Enable API access under Coolify settings.
- Create an API token with deploy permission.
- Open the SatOIDC application, go to Webhooks, and copy the deploy webhook.
- Put runtime variables in the Coolify application environment.

## Production Environment

SatOIDC currently reads the runtime variable names shown below. The future
Setup Wizard will introduce `SATOIDC_*` aliases such as
`SATOIDC_ISSUER`, `SATOIDC_DATABASE_URL`, and `SATOIDC_SECRET_KEY`, but those
aliases are contract targets until runtime support is implemented. Use current
names for production deployments today.

Minimum production environment values:

```env
POSTGRES_USER=satoidc
POSTGRES_PASSWORD=change-to-a-long-random-password
POSTGRES_DB=satoidc
SATOIDC_PORT=8000
APP_ENV=production
DOMAIN=example.com
OAUTH2_JWT_ISS=https://example.com
OAUTH2_JWT_SECRET_KEY=change-to-a-long-random-secret
OAUTH2_TOKEN_EXPIRES_IN=300
SESSION_MIDDLEWARE_SECRET_KEY=change-to-another-long-random-secret
SESSION_COOKIE_HTTPS_ONLY=true
OIDC_SIGNING_BACKEND=database
```

Use HTTPS through Coolify's proxy. `OAUTH2_JWT_ISS` must match the public issuer
URL clients will use.

Current precedence is process environment, then `.env`, then code defaults.
Future setup-wizard-compatible precedence is documented in
`specs/contracts/runtime-config.md`: `SATOIDC_*` direct values, then
`SATOIDC_*_FILE` values for supported secrets, then current direct names, then
current `_FILE` aliases, then persisted wizard-owned settings, then safe
defaults. Direct values win over `_FILE` values, and secrets must not be logged.

For hardened deployments with OpenBao or another Vault-compatible Transit
service, set:

```env
OIDC_SIGNING_BACKEND=transit
OIDC_TRANSIT_ADDR=https://openbao.example.com
OIDC_TRANSIT_TOKEN=change-to-a-scoped-transit-token
OIDC_TRANSIT_MOUNT=transit
OIDC_TRANSIT_KEY_NAME=satoidc-id-token
```

The Transit token must be allowed to create/read/rotate the configured key,
export public key material, and sign with `pkcs1v15` through the Transit API.

## Manual Deployment

The same deployment trigger can be run manually:

```bash
curl --fail --request GET "$COOLIFY_WEBHOOK" \
  --header "Authorization: Bearer $COOLIFY_TOKEN"
```

## Operational Notes

- Keep production environment variables in Coolify; do not commit `.env`.
- Back up the PostgreSQL volume before risky changes.
- The setup wizard runs on startup until a root user exists.
- PostgreSQL is the expected production database for the Compose stack.
