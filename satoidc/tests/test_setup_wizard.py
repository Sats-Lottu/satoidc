import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from starlette.status import HTTP_303_SEE_OTHER, HTTP_307_TEMPORARY_REDIRECT

from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from satoidc.models.database import get_session
from setup_wizard.__main__ import create_app
from setup_wizard.get_root import (
    authenticate_root_user,
    exists_root_user,
    has_active_root_permission,
    parse_root_user_id,
)


def test_setup_wizard_import_does_not_load_app_pages():
    project_dir = Path(__file__).resolve().parents[1]
    code = (
        "import sys;"
        "import setup_wizard.__main__;"
        "raise SystemExit('satoidc.routes.profile' in sys.modules)"
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project_dir,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_setup_wizard_builds_fastapi_app():
    app = create_app(mount_ui=False)

    assert app.title == "SatOIDC Setup Wizard"


def test_setup_wizard_redirects_unknown_routes():
    app = create_app(mount_ui=False)
    client = TestClient(app, follow_redirects=False)

    response = client.get("/profile")

    assert response.status_code == HTTP_307_TEMPORARY_REDIRECT
    assert response.headers["location"] == "/"


async def test_setup_root_login_sets_http_session(db_session, make_user):
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

    async def override_get_session():
        yield db_session

    app = create_app(mount_ui=False)
    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app, follow_redirects=False) as client:
            response = client.post(
                "/setup/root-login",
                data={
                    "identifier": user.login,
                    "password": "StrongPass1!",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/"
    assert "setup_session" in response.cookies


def test_setup_wizard_parses_root_user_ids():
    user_id = uuid4()

    assert parse_root_user_id(user_id.hex) == user_id
    assert parse_root_user_id(str(user_id)) == user_id
    assert parse_root_user_id(user_id) == user_id
    assert parse_root_user_id(None) is None
    assert parse_root_user_id("not-a-uuid") is None


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
