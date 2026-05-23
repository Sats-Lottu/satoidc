from datetime import datetime, timezone

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

import satoidc.services.setup_lock as setup_lock_module
import satoidc.settings as settings_module
from satoidc.models import SetupState
from satoidc.services.setup_lock import (
    SetupLockUnavailableError,
    acquire_setup_lock,
    fail_setup_lock,
    release_setup_lock,
)
from satoidc.settings import Settings


async def test_setup_state_persists_with_real_database(db_session):
    setup_state = SetupState(
        state="completed",
        version=1,
        completed_by="system",
        config_hash="sha256:abc123",
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(setup_state)
    await db_session.commit()

    stored_state = await db_session.scalar(select(SetupState))

    assert stored_state is not None
    assert stored_state.id == 1
    assert stored_state.state == "completed"
    assert stored_state.version == 1
    assert stored_state.completed_by == "system"
    assert stored_state.config_hash == "sha256:abc123"
    assert stored_state.last_error is None
    assert isinstance(stored_state.created_at, datetime)
    assert isinstance(stored_state.updated_at, datetime)


async def test_setup_state_rejects_invalid_state(db_session):
    db_session.add(SetupState(state="unknown"))

    with pytest.raises(IntegrityError):
        await db_session.commit()


async def test_setup_lock_blocks_second_setup_attempt(db_session):
    first_lock = await acquire_setup_lock(db_session, actor="setup-a")

    with pytest.raises(SetupLockUnavailableError) as exc_info:
        await acquire_setup_lock(db_session, actor="setup-b")

    stored_state = await db_session.scalar(select(SetupState))

    assert first_lock.state_id == 1
    assert stored_state is not None
    assert stored_state.state == "applying"
    assert exc_info.value.diagnostics.current_state == "applying"
    assert (
        exc_info.value.diagnostics.message
        == "Setup is locked by another setup attempt."
    )


async def test_setup_lock_blocks_second_database_session(db_session):
    session_factory = sessionmaker(
        db_session.bind, class_=AsyncSession, expire_on_commit=False
    )

    async with session_factory() as setup_a, session_factory() as setup_b:
        await acquire_setup_lock(setup_a, actor="setup-a")

        with pytest.raises(SetupLockUnavailableError) as exc_info:
            await acquire_setup_lock(setup_b, actor="setup-b")

        stored_state = await setup_b.get(SetupState, 1)

    assert stored_state is not None
    assert stored_state.state == "applying"
    assert exc_info.value.diagnostics.current_state == "applying"


async def test_setup_lock_release_marks_setup_completed(db_session):
    lock = await acquire_setup_lock(db_session, actor="setup-runner")

    completed_state = await release_setup_lock(
        db_session,
        lock,
        completed_by="system",
        config_hash="sha256:setup",
    )

    assert completed_state.state == "completed"
    assert completed_state.completed_by == "system"
    assert completed_state.config_hash == "sha256:setup"
    assert completed_state.last_error is None
    assert completed_state.completed_at is not None

    with pytest.raises(SetupLockUnavailableError) as exc_info:
        await acquire_setup_lock(db_session, actor="setup-b")

    assert exc_info.value.diagnostics.current_state == "completed"
    assert exc_info.value.diagnostics.message == "Setup has already completed."


async def test_setup_lock_fail_is_recoverable(db_session):
    failed_lock = await acquire_setup_lock(db_session, actor="setup-runner")

    failed_state = await fail_setup_lock(
        db_session,
        failed_lock,
        error="database write failed",
    )

    assert failed_state.state == "failed"
    assert failed_state.last_error == "database write failed"
    assert failed_state.completed_at is None

    recovered_lock = await acquire_setup_lock(db_session, actor="setup-retry")
    recovered_state = await db_session.scalar(select(SetupState))

    assert recovered_lock.state_id == 1
    assert recovered_state is not None
    assert recovered_state.state == "applying"
    assert recovered_state.last_error is None


async def test_setup_lock_release_requires_active_lock(db_session):
    lock = await acquire_setup_lock(db_session, actor="setup-runner")
    await fail_setup_lock(db_session, lock, error="recoverable failure")

    with pytest.raises(SetupLockUnavailableError) as exc_info:
        await release_setup_lock(db_session, lock)

    assert exc_info.value.diagnostics.current_state == "failed"


async def test_setup_lock_reports_missing_state(db_session):
    with pytest.raises(SetupLockUnavailableError) as exc_info:
        await setup_lock_module._raise_locked(db_session)

    assert exc_info.value.diagnostics.current_state == "missing"
    assert (
        exc_info.value.diagnostics.message
        == "Setup lock could not be acquired."
    )


async def test_create_applying_setup_state_handles_insert_race(
    db_session, monkeypatch
):
    original_flush = db_session.flush
    calls = 0

    async def race_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise IntegrityError("insert", {}, Exception("duplicate"))
        return await original_flush(*args, **kwargs)

    monkeypatch.setattr(db_session, "flush", race_once)

    state = await setup_lock_module._create_applying_setup_state(db_session)

    assert state is None


def test_setup_state_migration_creates_sqlite_table(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_path = tmp_path / "setup-state-migration.db"
    async_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    sync_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings_module,
        "ENV",
        Settings(DATABASE_URL=async_url, SYNC_DATABASE_URL=sync_url),
    )

    alembic_config = Config("alembic.ini")
    command.upgrade(alembic_config, "head")

    engine = create_engine(sync_url, connect_args={"check_same_thread": False})
    try:
        inspector = inspect(engine)
        columns = {
            column["name"] for column in inspector.get_columns("setup_state")
        }

        with engine.begin() as connection:
            connection.execute(
                text(
                    "insert into setup_state "
                    "(id, state, version, completed_by, config_hash) "
                    "values "
                    "(1, 'completed', 1, 'system', 'sha256:abc123')"
                )
            )
            stored = connection.execute(
                text(
                    "select state, version, completed_by, config_hash "
                    "from setup_state where id = 1"
                )
            ).one()
    finally:
        engine.dispose()

    assert {
        "id",
        "state",
        "version",
        "completed_by",
        "config_hash",
        "last_error",
        "completed_at",
        "created_at",
        "updated_at",
    }.issubset(columns)
    assert stored == ("completed", 1, "system", "sha256:abc123")
