import pytest
from fastapi.testclient import TestClient
from starlette.status import HTTP_303_SEE_OTHER

from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from satoidc.models.database import get_session
from setup_wizard.__main__ import create_app
from setup_wizard.routes import store_lnurl_root_login_ticket

pytestmark = pytest.mark.setup


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


async def test_setup_root_login_rejects_bad_credentials(
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
                    "password": "WrongPass1!",
                },
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/?setup_error=invalid-root-login"
    assert "setup_session" not in response.cookies


async def test_setup_logout_clears_setup_session_cookie(
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

    async def override_get_session():
        yield db_session

    app = create_app(mount_ui=False)
    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app, follow_redirects=False) as client:
            login_response = client.post(
                "/setup/root-login",
                data={
                    "identifier": user.login,
                    "password": "StrongPass1!",
                },
            )
            response = client.get("/setup/logout")
    finally:
        app.dependency_overrides.clear()

    assert login_response.status_code == HTTP_303_SEE_OTHER
    assert response.status_code == HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/"
    assert response.cookies.get("setup_session") is None


async def test_setup_lnurl_login_sets_http_session(db_session, make_user):
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

    async def override_get_session():
        yield db_session

    app = create_app(mount_ui=False)
    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app, follow_redirects=False) as client:
            ticket = store_lnurl_root_login_ticket(user.id)
            response = client.get(
                f"/setup/complete-lnurl-login?ticket={ticket}"
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/"
    assert "setup_session" in response.cookies


async def test_setup_lnurl_login_rejects_invalid_ticket(db_session):
    async def override_get_session():
        yield db_session

    app = create_app(mount_ui=False)
    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app, follow_redirects=False) as client:
            response = client.get(
                "/setup/complete-lnurl-login?ticket=missing"
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == HTTP_303_SEE_OTHER
    assert (
        response.headers["location"]
        == "/?setup_error=invalid-lnurl-root-login"
    )
    assert "setup_session" not in response.cookies
