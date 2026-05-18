# SatOIDC Operator Runbook

Updated: 2026-05-18

This runbook is for self-hosted operators running SatOIDC with Docker Compose
and PostgreSQL. SQLite remains supported for local development, tests, demos,
and small single-node deployments, but PostgreSQL is the expected production
database.

Use this with:

- [VPS Deployment](../deployment/vps.md)
- [Database Support Matrix](../database-support-matrix.md)
- [Reverse Proxy Operations](reverse-proxy.md)
- [Email Operations](email.md)
- [Transit Signing Operations](transit.md)

## Operating Baseline

Production operators should confirm these conditions before serving public
traffic:

- `APP_ENV=production`
- `OAUTH2_JWT_ISS` is the public HTTPS issuer URL.
- `SESSION_COOKIE_HTTPS_ONLY=true`
- `DATABASE_URL` and `SYNC_DATABASE_URL` point to the same PostgreSQL database.
- Placeholder secrets from `.env.example` have been replaced.
- A TLS-terminating reverse proxy protects public traffic and applies auth
  rate limits as described in [Reverse Proxy Operations](reverse-proxy.md).
- The reverse proxy preserves real client IPs for rate-limit keys; public
  requests cannot spoof trusted forwarding headers.
- Runtime secrets and database credentials are stored in the deployment
  platform, not committed to the repository.
- The first root account has been created through the setup wizard.

## Health Checks

Run these checks after deployment, restore, upgrade, or incident recovery.

```bash
docker compose --env-file .env ps
docker compose --env-file .env exec database pg_isready \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB"
curl --fail --show-error https://id.example.com/
curl --fail --show-error \
  https://id.example.com/.well-known/openid-configuration
curl --fail --show-error https://id.example.com/.well-known/jwks.json
```

Expected results:

- `database` is healthy.
- `satoidc` is running.
- `/` returns a successful HTTP response.
- Discovery JSON contains the public issuer and `jwks_uri`.
- JWKS returns public key material only.

If the app is behind a proxy, also confirm the public URL, issuer, and callback
URLs use HTTPS and the expected host. A mismatch in `OAUTH2_JWT_ISS` breaks OIDC
clients even when the container itself is healthy.

For public or staging deployments, also run the
[reverse-proxy manual validation checklist](reverse-proxy.md#manual-validation-checklist)
after proxy changes, DNS changes, TLS renewal changes, or load-balancer changes.

## PostgreSQL Backups

Take backups before upgrades, migration experiments, secret rotation, signing
backend changes, or any incident repair that might change persistent data.

From the deployment directory that contains `compose.yaml` and `.env`:

```bash
set -a
. ./.env
set +a

: "${POSTGRES_USER:=app_user}"
: "${POSTGRES_DB:=app_db}"

mkdir -p backups
backup_file="backups/satoidc-$(date -u +%Y%m%dT%H%M%SZ).dump"

docker compose --env-file .env exec -T database pg_dump \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  --format=custom \
  --no-owner \
  --no-acl \
  > "$backup_file"

ls -lh "$backup_file"
```

Minimum backup validation:

```bash
docker compose --env-file .env exec -T database pg_restore --list \
  < "$backup_file" \
  > /tmp/satoidc-backup-contents.txt
head /tmp/satoidc-backup-contents.txt
```

Store backup files away from the VPS or host running SatOIDC. A backup that
lives only on the same host does not protect against disk loss, host compromise,
or accidental volume deletion.

## PostgreSQL Restore

Restore only into a disposable environment first unless this is an emergency.
For production recovery, stop the application before replacing the database so
Authlib, FastAPI routes, and setup checks cannot write during restore.

```bash
set -a
. ./.env
set +a

: "${POSTGRES_USER:=app_user}"
: "${POSTGRES_DB:=app_db}"
: "${BACKUP_FILE:?set BACKUP_FILE to the .dump file to restore}"

docker compose --env-file .env stop satoidc

docker compose --env-file .env exec -T database psql \
  -U "$POSTGRES_USER" \
  -d postgres \
  -c "SELECT pg_terminate_backend(pid)
      FROM pg_stat_activity
      WHERE datname = '$POSTGRES_DB'
      AND pid <> pg_backend_pid();"

docker compose --env-file .env exec -T database dropdb \
  -U "$POSTGRES_USER" --if-exists "$POSTGRES_DB"

docker compose --env-file .env exec -T database createdb \
  -U "$POSTGRES_USER" "$POSTGRES_DB"

docker compose --env-file .env exec -T database pg_restore \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" \
  --no-owner \
  --no-acl \
  < "$BACKUP_FILE"

docker compose --env-file .env up -d satoidc
```

After restore, run the [Health Checks](#health-checks). If the restored backup
is from an older application version, the entrypoint runs `alembic upgrade
head` before serving the app.

## SQLite Local Backups

SQLite files such as `satoidc/satoidc.db` and `satoidc/database.db` are local
runtime data. Do not commit them.

For local development, stop the app before copying the SQLite database:

```bash
cd satoidc
cp satoidc.db "satoidc.$(date -u +%Y%m%dT%H%M%SZ).db"
```

If a local SQLite database reports an Alembic revision missing from
`migrations/versions/`, use
[Local Development Troubleshooting](../local-development-troubleshooting.md)
before deleting, stamping, or recreating the database.

## Upgrade Checklist

Use this process for production or production-like Compose deployments.

1. Read release notes, migration notes, and changed environment variables.
2. Confirm CI passed for the revision being deployed.
3. Take a PostgreSQL backup and validate it with the backup validation command.
4. Save current deployment metadata:

   ```bash
   git rev-parse HEAD
   docker compose --env-file .env ps
   docker compose --env-file .env logs --tail 100 satoidc
   ```

5. Pull or deploy the new revision.
6. Start the stack:

   ```bash
   docker compose --env-file .env up -d --build
   ```

7. Watch startup logs until migrations, setup checks, and FastAPI startup
   complete:

   ```bash
   docker compose --env-file .env logs -f satoidc
   ```

8. Run the [Health Checks](#health-checks).
9. Exercise one real OIDC client login in a low-risk window.
10. Keep the pre-upgrade backup until the deployment has survived normal
    traffic and the next scheduled backup has completed.

Rollback expectation: rolling the application image or Git revision back may be
safe for code-only changes, but database migrations may not be reversible. If a
new migration changed schema or data, the reliable rollback path is restoring
the pre-upgrade database backup and then starting the previous application
revision.

## Alembic Failure Handling

SatOIDC runs `poetry run alembic upgrade head` during container startup. Treat
migration failures as production incidents because the app may not be serving
traffic and the database may be partly changed.

Immediate response:

1. Do not run `alembic stamp`, edit migration rows, or delete tables in
   production as a first response.
2. Stop the application container if it is crash-looping:

   ```bash
   docker compose --env-file .env stop satoidc
   ```

3. Keep PostgreSQL running and take a fresh backup of the current failed state.
4. Capture logs:

   ```bash
   docker compose --env-file .env logs --tail 200 satoidc
   docker compose --env-file .env logs --tail 100 database
   ```

5. Inspect the current Alembic revision with the app image and environment:

   ```bash
   docker compose --env-file .env run --rm --no-deps \
     --entrypoint sh satoidc \
     -lc 'poetry run alembic current && poetry run alembic heads'
   ```

6. Compare the failed revision with `satoidc/migrations/versions/`.

Recovery options:

- If the failure is configuration or connectivity, fix the environment or
  database reachability, then restart `satoidc`.
- If the database revision is from a newer app version, deploy the matching app
  version or restore a backup compatible with the current app.
- If a migration failed after partially applying changes, prefer restoring the
  pre-upgrade backup. Only use manual SQL repair when a human operator has read
  the migration and can prove the database state is consistent.
- For local SQLite-only revision drift, use
  [Local Development Troubleshooting](../local-development-troubleshooting.md).

## Incident Response

Use this checklist for outages, suspected compromise, broken login, failed
upgrades, signing failures, or database errors.

1. Declare the incident and record start time, public symptoms, suspected
   trigger, current Git revision, and current container status.
2. Preserve evidence before changing state:

   ```bash
   docker compose --env-file .env ps
   docker compose --env-file .env logs --tail 300 satoidc
   docker compose --env-file .env logs --tail 200 database
   ```

3. If data corruption, unsafe migration, or compromise is suspected, stop the
   app and take a PostgreSQL backup of the current state.
4. Check public health, discovery, JWKS, database health, proxy status, TLS,
   forwarded headers, and reverse-proxy auth rate limits.
5. Identify the affected surface:

   | Surface | First checks |
   | --- | --- |
   | Login/register/recovery | Reverse proxy rate limits, app logs, database connectivity, email mode |
   | OIDC clients | issuer value, discovery JSON, redirect URI configuration, token endpoint logs |
   | JWKS/ID Tokens | signing backend, active key state, Transit availability if configured |
   | LNURL-auth | callback reachability, HTTPS issuer, challenge expiration, wallet callback logs |
   | Admin/setup | root user existence, setup wizard logs, session cookie settings |

6. Mitigate narrowly. Prefer reverting the last deploy, disabling public traffic
   at the proxy, or restoring from a known-good backup over ad hoc data edits.
7. After recovery, run the [Health Checks](#health-checks), test one login, and
   document the root cause and follow-up work.

## Related Operations

- Reverse proxy, TLS, forwarded headers, and delegated auth rate limiting:
  [Reverse Proxy Operations](reverse-proxy.md).
- SMTP, console, and disabled email sender modes, token TTLs, validation, and
  recovery troubleshooting: [Email Operations](email.md).
- Database and OpenBao/Vault-compatible Transit signing backends, required
  variables, failure modes, and fallback: [Transit Signing Operations](transit.md).
- Current runtime settings are listed in
  [Runtime Configuration Contract](../../specs/contracts/runtime-config.md).
