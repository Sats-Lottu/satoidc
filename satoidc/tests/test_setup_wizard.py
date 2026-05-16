from datetime import datetime, timedelta, timezone

from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from setup_wizard.__main__ import create_app
from setup_wizard.get_root import (
    authenticate_root_user,
    exists_root_user,
    has_active_root_permission,
)


def test_setup_wizard_builds_fastapi_app():
    app = create_app(mount_ui=False)

    assert app.title == "SatOIDC Setup Wizard"


async def test_setup_wizard_detects_missing_root_user(db_session):
    assert await exists_root_user() is False


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
