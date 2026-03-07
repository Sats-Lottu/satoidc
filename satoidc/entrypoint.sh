#!/bin/sh

# Executa as migrações do banco de dados
poetry run alembic upgrade head

# Wizard (só bloqueia se não existir admin; ao finalizar ele encerra sozinho)
poetry run python -m setup_wizard

# Inicia a aplicação
poetry run fastapi run --host 0.0.0.0 --port 8000 satoidc