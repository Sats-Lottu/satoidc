from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import setup_wizard.get_root as get_root_module
from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from setup_wizard.get_root import (
    authenticate_root_user,
    database_schema_ready,
    exists_root_user,
    has_active_root_permission,
    parse_root_user_id,
)
from setup_wizard.routes import SETUP_ROOT_USER_ID_KEY, stored_root_has_access

pytestmark = pytest.mark.setup


def test_setup_wizard_parses_root_user_ids():
    user_id = uuid4()

    assert parse_root_user_id(user_id.hex) == user_id
    assert parse_root_user_id(str(user_id)) == user_id
    assert parse_root_user_id(user_id) == user_id
    assert parse_root_user_id(None) is None
    assert parse_root_user_id("not-a-uuid") is None


async def test_setup_wizard_detects_missing_root_user(db_session):
    assert await exists_root_user() is False


async def test_setup_wizard_detects_ready_database_schema(db_session):
    assert await database_schema_ready() is True


async def test_setup_wizard_handles_missing_database_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    database_path = tmp_path / "empty.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path.as_posix()}"
    )

    async def empty_get_session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    monkeypatch.setattr(get_root_module, "get_session", empty_get_session)

    try:
        assert await database_schema_ready() is False
        assert await exists_root_user() is False
    finally:
        await engine.dispose()


async def test_setup_wizard_detects_existing_root_user(
    db_session, make_user
):
    user = await make_user()
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=None,
            reason="test root user",
        )
    )
    await db_session.commit()

    assert await exists_root_user() is True


async def test_setup_wizard_authenticates_active_root_user(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=None,
            reason="test root user",
        )
    )
    await db_session.commit()

    authenticated = await authenticate_root_user(
        db_session, user.login, "StrongPass1!"
    )

    assert authenticated is not None
    assert authenticated.id == user.id
    assert await has_active_root_permission(db_session, user.id) is True


async def test_setup_wizard_authenticates_root_by_email(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=None,
            reason="test root user",
        )
    )
    await db_session.commit()

    authenticated = await authenticate_root_user(
        db_session, user.email.upper(), "StrongPass1!"
    )

    assert authenticated is not None
    assert authenticated.id == user.id


async def test_setup_wizard_rejects_non_root_credentials(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))

    authenticated = await authenticate_root_user(
        db_session, user.login, "StrongPass1!"
    )

    assert authenticated is None
    assert await has_active_root_permission(db_session, user.id) is False


async def test_setup_wizard_rejects_invalid_root_credentials(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=None,
            reason="test root user",
        )
    )
    await db_session.commit()

    authenticated = await authenticate_root_user(
        db_session, user.email, "WrongPass1!"
    )

    assert authenticated is None


async def test_setup_wizard_rejects_expired_root_permission(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=datetime.now(timezone.utc)
            - timedelta(minutes=1),
            reason="expired root user",
        )
    )
    await db_session.commit()

    authenticated = await authenticate_root_user(
        db_session, user.login, "StrongPass1!"
    )

    assert authenticated is None
    assert await has_active_root_permission(db_session, user.id) is False


async def test_setup_wizard_keeps_valid_root_session(db_session, make_user):
    user = await make_user()
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=None,
            reason="test root user",
        )
    )
    await db_session.commit()
    request = SimpleNamespace(session={SETUP_ROOT_USER_ID_KEY: user.id.hex})

    assert await stored_root_has_access(db_session, request) is True
    assert request.session[SETUP_ROOT_USER_ID_KEY] == user.id.hex


async def test_setup_wizard_clears_invalid_root_session(db_session):
    request = SimpleNamespace(session={SETUP_ROOT_USER_ID_KEY: "invalid"})

    assert await stored_root_has_access(db_session, request) is False
    assert SETUP_ROOT_USER_ID_KEY not in request.session
