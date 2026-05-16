#!/bin/sh
set -eu

echo "Validating bootstrap configuration..."
poetry run python -m setup_wizard.bootstrap

echo "Running database migrations..."
poetry run alembic upgrade head

echo "Running setup wizard if a root user is missing..."
poetry run python -m setup_wizard

echo "Starting SatOIDC..."
exec poetry run fastapi run --host 0.0.0.0 --port 8000 satoidc
