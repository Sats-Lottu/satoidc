from datetime import datetime, timezone

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

import satoidc.settings as settings_module
from satoidc.models import SetupState
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
