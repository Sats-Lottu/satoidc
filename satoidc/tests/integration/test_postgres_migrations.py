import asyncio
import sys
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from docker.errors import DockerException
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine
from testcontainers.core.exceptions import ContainerStartException
from testcontainers.postgres import PostgresContainer

import satoidc.settings as settings_module
from satoidc.settings import Settings

pytestmark = [pytest.mark.integration, pytest.mark.container]


@pytest.fixture
def postgres_urls() -> Iterator[tuple[str, str]]:
    try:
        container = PostgresContainer(
            "postgres:16-alpine",
            driver="psycopg",
            dbname="satoidc_test",
        )
    except DockerException as exc:
        pytest.skip(f"Docker is not available for Testcontainers: {exc}")

    try:
        with container as postgres:
            sync_url = postgres.get_connection_url(driver="psycopg")
            yield sync_url, sync_url
    except (ContainerStartException, DockerException) as exc:
        pytest.skip(f"PostgreSQL Testcontainer could not start: {exc}")


def test_postgres_migrations_support_sync_and_async_sessions(
    monkeypatch: pytest.MonkeyPatch,
    postgres_urls: tuple[str, str],
) -> None:
    async_url, sync_url = postgres_urls

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    monkeypatch.setattr(
        settings_module,
        "ENV",
        Settings(DATABASE_URL=async_url, SYNC_DATABASE_URL=sync_url),
    )

    alembic_config = Config("alembic.ini")
    command.upgrade(alembic_config, "head")

    sync_engine = create_engine(sync_url)

    async def read_nickname_from_async_engine() -> str | None:
        async_engine = create_async_engine(async_url)
        try:
            async with async_engine.connect() as connection:
                return await connection.scalar(
                    text(
                        "select nickname from users "
                        "where id = "
                        "'00000000-0000-0000-0000-000000000001'"
                    )
                )
        finally:
            await async_engine.dispose()

    try:
        with sync_engine.begin() as connection:
            tables = set(
                connection.execute(
                    text(
                        "select tablename from pg_tables "
                        "where schemaname = 'public'"
                    )
                ).scalars()
            )
            connection.execute(
                text(
                    "insert into users "
                    "(id, nickname, is_active) "
                    "values "
                    "('00000000-0000-0000-0000-000000000001', "
                    "'Satoshi', true)"
                )
            )

        nickname = asyncio.run(read_nickname_from_async_engine())
    finally:
        sync_engine.dispose()

    assert {
        "users",
        "lnurl_auth_challenges",
        "oauth2_client",
        "oauth2_code",
        "oauth2_token",
        "permissions",
        "permission_requests",
        "oidc_signing_keys",
        "oidc_signing_key_audit_events",
        "setup_state",
    }.issubset(tables)
    assert nickname == "Satoshi"
