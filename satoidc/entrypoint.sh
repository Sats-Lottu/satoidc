#!/bin/sh
set -eu

echo "Validating bootstrap configuration..."
poetry run python -m setup_wizard.bootstrap
if [ -n "${SETUP_GENERATED_SECRETS_PATH:-}" ] && [ -f "$SETUP_GENERATED_SECRETS_PATH" ]; then
  . "$SETUP_GENERATED_SECRETS_PATH"
fi

echo "Running database migrations..."
poetry run alembic upgrade head

echo "Running setup wizard if a root user is missing..."
poetry run python -m setup_wizard

echo "Validating database-backed bootstrap readiness..."
poetry run python -m setup_wizard.bootstrap --database-state

echo "Starting SatOIDC..."
exec poetry run fastapi run --host 0.0.0.0 --port 8000 satoidc/main.py
