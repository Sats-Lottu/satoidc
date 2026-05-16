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
```

Use HTTPS through Coolify's proxy. `OAUTH2_JWT_ISS` must match the public issuer
URL clients will use.

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
