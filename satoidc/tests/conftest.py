from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

import satoidc.auth.oauth2 as oauth2_module
import satoidc.models.database as database_module
from satoidc.main import app
from satoidc.models import User, table_registry
from satoidc.models.database import get_session

SENSITIVE_LOG_VALUES = (
    "password-secret",
    "access-token-secret",
    "refresh-token-secret",
    "private-jwk-secret",
    "client-secret-value",
)


@pytest.fixture
def assert_no_sensitive_log_values(caplog):
    def _assert_no_sensitive_log_values(*values: str) -> None:
        for value in (*SENSITIVE_LOG_VALUES, *values):
            assert value not in caplog.text

    return _assert_no_sensitive_log_values


@pytest.fixture
async def db_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[AsyncSession]:
    database_path = tmp_path / "satoidc-test.db"
    async_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    sync_url = f"sqlite:///{database_path.as_posix()}"

    async_engine = create_async_engine(async_url)
    sync_engine = create_engine(
        sync_url, connect_args={"check_same_thread": False}
    )
    testing_session_local = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=sync_engine,
    )

    monkeypatch.setattr(database_module, "engine", async_engine)
    monkeypatch.setattr(database_module, "sync_engine", sync_engine)
    monkeypatch.setattr(database_module, "SessionLocal", testing_session_local)
    database_module.SyncSession.remove()
    database_module.SyncSession.configure(bind=sync_engine)
    monkeypatch.setattr(database_module, "db", database_module.SyncSession)
    monkeypatch.setattr(oauth2_module, "db", database_module.SyncSession)

    async with async_engine.begin() as conn:
        await conn.run_sync(table_registry.metadata.create_all)

    try:
        async with AsyncSession(
            async_engine, expire_on_commit=False
        ) as session:
            yield session
    finally:
        database_module.SyncSession.remove()
        await async_engine.dispose()
        sync_engine.dispose()


@pytest.fixture
def app_client(db_session: AsyncSession) -> Iterator[TestClient]:
    async def override_get_session() -> AsyncIterator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def make_user(db_session: AsyncSession):
    async def _make_user(
        *,
        login: str = "satoshi1",
        email: str = "satoshi@example.com",
        password_hash: str | None = None,
        nickname: str = "Satoshi",
        lnurl_pubkey: str | None = None,
    ) -> User:
        user = User(
            lnurl_pubkey=lnurl_pubkey,
            email=email,
            login=login,
            password_hash=password_hash,
            nickname=nickname,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _make_user
