import logging
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from types import SimpleNamespace
from uuid import uuid4

import pytest
from starlette.requests import Request

import satoidc.auth.security as security_module
from satoidc.auth.middleware import AuthMiddleware, is_public_path
from satoidc.auth.security import (
    authorize_page_request,
    get_active_user_permissions,
    hash_password,
    is_authorized,
    page_security,
    verify_password,
)
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from satoidc.utils import safe_redirect


def test_password_hashing_uses_real_hasher():
    password_hash = hash_password("StrongPass1!")

    assert password_hash != "StrongPass1!"
    assert verify_password("StrongPass1!", password_hash)
    assert not verify_password("WrongPass1!", password_hash)


def test_root_permission_authorizes_everything():
    assert is_authorized(
        {PermissionsEnum.ROOT},
        {PermissionsEnum.ADMIN, PermissionsEnum.SUPPORT},
    )


def test_permission_modes_require_all_or_any():
    user_permissions = {PermissionsEnum.ADMIN}

    assert is_authorized(
        user_permissions,
        {PermissionsEnum.ADMIN, PermissionsEnum.SUPPORT},
        mode="any",
    )
    assert not is_authorized(
        user_permissions,
        {PermissionsEnum.ADMIN, PermissionsEnum.SUPPORT},
        mode="all",
    )
    assert is_authorized(
        {PermissionsEnum.DEVELOPER},
        {PermissionsEnum.DEVELOPER, PermissionsEnum.ADMIN},
        mode="any",
    )


def test_invalid_permission_mode_is_rejected():
    with pytest.raises(ValueError, match="Invalid permission mode"):
        is_authorized(
            {PermissionsEnum.ADMIN},
            {PermissionsEnum.ADMIN},
            mode="invalid",
        )


async def test_active_user_permissions_filters_disabled_and_expired(
    db_session, make_user
):
    user = await make_user()
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            Permission(
                user_id=user.id,
                granted_by=None,
                permission_type=PermissionsEnum.ADMIN,
                expiration_date=None,
                reason="active",
            ),
            Permission(
                user_id=user.id,
                granted_by=None,
                permission_type=PermissionsEnum.SUPPORT,
                expiration_date=now + timedelta(days=1),
                reason="disabled",
                disabled=True,
            ),
            Permission(
                user_id=user.id,
                granted_by=None,
                permission_type=PermissionsEnum.ROOT,
                expiration_date=now - timedelta(days=1),
                reason="expired",
            ),
        ]
    )
    await db_session.commit()

    permissions = await get_active_user_permissions(user.id)

    assert permissions == {str(PermissionsEnum.ADMIN)}


async def test_authorize_page_request_redirects_for_missing_or_invalid_session(
):
    missing_session = SimpleNamespace(session={})
    invalid_session = SimpleNamespace(session={"user_id": "not-a-uuid"})

    missing_response = await authorize_page_request(
        missing_session, {PermissionsEnum.ROOT}
    )
    invalid_response = await authorize_page_request(
        invalid_session, {PermissionsEnum.ROOT}
    )

    assert missing_response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    assert missing_response.headers["location"] == "/login"
    assert invalid_response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    assert invalid_response.headers["location"] == "/login"


async def test_authorize_page_request_redirects_for_missing_permissions():
    request = SimpleNamespace(session={"user_id": uuid4().hex})

    response = await authorize_page_request(
        request,
        {PermissionsEnum.ROOT},
        session_factory=_empty_session_factory,
    )

    assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    assert response.headers["location"] == "/forbidden"


async def _empty_session_factory():
    if False:
        yield None


async def test_authorize_page_request_allows_authorized_user(
    db_session, make_user
):
    user = await make_user()
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=None,
            reason="root",
        )
    )
    await db_session.commit()
    request = SimpleNamespace(session={"user_id": user.id.hex})

    assert (
        await authorize_page_request(request, {PermissionsEnum.ADMIN}) is None
    )


async def test_page_security_decorator_returns_page_result(monkeypatch):
    request = SimpleNamespace(session={"user_id": uuid4().hex})
    monkeypatch.setattr(
        security_module,
        "ui",
        SimpleNamespace(
            context=SimpleNamespace(client=SimpleNamespace(request=request))
        ),
    )

    async def allow_access(*args, **kwargs):
        return None

    monkeypatch.setattr(
        security_module, "authorize_page_request", allow_access
    )

    @page_security(permissions=[PermissionsEnum.ADMIN])
    async def page():
        return "rendered"

    assert await page() == "rendered"


async def test_page_security_decorator_returns_redirect(monkeypatch):
    request = SimpleNamespace(session={})
    redirect = SimpleNamespace(status_code=HTTPStatus.TEMPORARY_REDIRECT)
    monkeypatch.setattr(
        security_module,
        "ui",
        SimpleNamespace(
            context=SimpleNamespace(client=SimpleNamespace(request=request))
        ),
    )

    async def deny_access(*args, **kwargs):
        return redirect

    monkeypatch.setattr(security_module, "authorize_page_request", deny_access)

    @page_security()
    async def page():
        raise AssertionError("protected page should not render")

    assert await page() is redirect


def test_safe_redirect_accepts_only_relative_paths():
    assert safe_redirect("/profile") == "/profile"
    assert safe_redirect("/profile?tab=wallet") == "/profile?tab=wallet"
    assert safe_redirect(None) == "/"
    assert safe_redirect("") == "/"
    assert safe_redirect("profile") == "/"
    assert safe_redirect("https://evil.example/login") == "/"
    assert safe_redirect("//evil.example/login") == "/"


def test_auth_middleware_redirects_protected_route(app_client):
    response = app_client.get("/profile?tab=wallet", follow_redirects=False)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/login?redirect_to=%2Fprofile%3Ftab%3Dwallet"
    )


def test_auth_middleware_logs_missing_session_without_query_secret(
    app_client, caplog
):
    caplog.set_level(logging.INFO, logger="satoidc.auth.middleware")

    response = app_client.get(
        "/profile?token=secret-token", follow_redirects=False
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert any(
        record.event_name == "auth.session_missing"
        and record.component == "auth_middleware"
        and record.path == "/profile"
        for record in caplog.records
    )
    assert "secret-token" not in caplog.text


def test_auth_middleware_allows_public_oauth_route(app_client):
    response = app_client.get("/.well-known/jwks.json")

    assert response.status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/login",
        "/oauth",
        "/oauth/token",
        "/api",
        "/api/status",
        "/auth/lnurl",
        "/auth/lnurl/callback",
        "/.well-known",
        "/.well-known/openid-configuration",
        "/_nicegui",
        "/_nicegui/static/app.js",
    ],
)
def test_public_path_classification_allows_exact_and_segment_paths(path):
    assert is_public_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "/oauth-settings",
        "/api-admin",
        "/auth/lnurlish",
        "/.well-knownness",
        "/_niceguiish",
    ],
)
def test_public_path_classification_rejects_lookalike_paths(path):
    assert not is_public_path(path)


@pytest.mark.parametrize(
    ("path", "expected_redirect"),
    [
        ("/oauth-settings", "/login?redirect_to=%2Foauth-settings"),
        ("/api-admin", "/login?redirect_to=%2Fapi-admin"),
        ("/.well-knownness", "/login?redirect_to=%2F.well-knownness"),
    ],
)
def test_auth_middleware_redirects_public_prefix_lookalikes(
    app_client, path, expected_redirect
):
    response = app_client.get(path, follow_redirects=False)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == expected_redirect


@pytest.mark.parametrize(
    "path",
    ["/oauth/token", "/api/status", "/.well-known/openid-configuration"],
)
def test_auth_middleware_does_not_redirect_public_segment_paths(
    app_client, path
):
    response = app_client.get(path, follow_redirects=False)

    assert response.status_code != HTTPStatus.SEE_OTHER
    assert not response.headers.get("location", "").startswith("/login")


async def test_auth_middleware_allows_authenticated_protected_route():
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/profile",
            "query_string": b"",
            "headers": [],
            "server": ("testserver", 80),
            "scheme": "https",
            "client": ("testclient", 50000),
            "state": {},
        }
    )
    request.scope["session"] = {"user_id": "user-1"}
    middleware = AuthMiddleware(app=lambda scope, receive, send: None)

    async def call_next(req):
        return "ok"

    assert await middleware.dispatch(request, call_next) == "ok"
