import asyncio

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = [pytest.mark.integration, pytest.mark.container]


def test_postgres_migrations_support_sync_and_async_sessions(
    migrated_postgres_urls: tuple[str, str],
) -> None:
    async_url, sync_url = migrated_postgres_urls

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
        "setup_runtime_settings",
    }.issubset(tables)
    assert nickname == "Satoshi"
