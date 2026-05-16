import logging
from datetime import UTC, datetime
from http import HTTPStatus
from types import SimpleNamespace
from uuid import uuid4

import pytest
from authlib.oauth2 import OAuth2Error
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.requests import Request

import satoidc.routes.oauth2 as oauth2_routes
from satoidc.routes.oauth2 import (
    authorize,
    introspect_token,
    jwks_root,
    revoke_token,
    token,
    userinfo,
)


def make_request(
    *,
    method: str = "GET",
    path: str = "/oauth/authorize",
    body: bytes = b"",
) -> Request:
    request = Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": b"",
            "headers": [],
            "server": ("testserver", 80),
            "scheme": "https",
            "client": ("testclient", 50000),
            "state": {},
        }
    )
    request._body = body
    return request


async def test_authorize_requires_logged_in_user(db_session):
    request = make_request(method="POST")
    request.scope["session"] = {}

    response = await authorize(db_session, request, "approve", "csrf")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.body == b'{"error":"login_required"}'


async def test_authorize_rejects_invalid_csrf(db_session, make_user, caplog):
    caplog.set_level(logging.INFO, logger="satoidc.routes.oauth2")
    user = await make_user()
    request = make_request(method="POST")
    request.scope["session"] = {"user_id": user.id.hex, "csrf_token": "good"}

    response = await authorize(db_session, request, "approve", "bad")

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.body == b'{"error":"invalid_csrf"}'
    assert any(
        record.event_name == "oauth.authorize_failed"
        and record.component == "oauth2"
        and record.reason == "invalid_csrf"
        for record in caplog.records
    )


async def test_authorize_rejects_invalid_or_unknown_session(
    db_session, make_user, monkeypatch
):
    request = make_request(method="POST")
    request.scope["session"] = {
        "user_id": "not-a-uuid",
        "csrf_token": "csrf",
    }

    response = await authorize(db_session, request, "approve", "csrf")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.body == b'{"error":"invalid_session"}'

    missing_user_request = make_request(method="POST")
    missing_user_request.scope["session"] = {
        "user_id": uuid4().hex,
        "csrf_token": "csrf",
    }

    response = await authorize(
        db_session, missing_user_request, "approve", "csrf"
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.body == b'{"error":"invalid_session"}'


async def test_authorize_translates_oauth_errors(
    db_session, make_user, monkeypatch
):
    user = await make_user()
    request = make_request(method="POST")
    request.scope["session"] = {"user_id": user.id.hex, "csrf_token": "csrf"}

    async def fake_threadpool(*args, **kwargs):
        raise OAuth2Error(
            error="invalid_request",
            description="bad request",
            status_code=400,
        )

    monkeypatch.setattr(oauth2_routes, "run_in_threadpool", fake_threadpool)

    response = await authorize(db_session, request, "approve", "csrf")

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.body == (
        b'{"error":"invalid_request","error_description":"bad request"}'
    )


async def test_authorize_returns_threadpool_response(
    db_session, make_user, monkeypatch
):
    user = await make_user()
    request = make_request(method="POST")
    request.scope["session"] = {"user_id": user.id.hex, "csrf_token": "csrf"}
    expected = JSONResponse({"ok": True})

    async def fake_threadpool(func, *args):
        return expected

    monkeypatch.setattr(oauth2_routes, "run_in_threadpool", fake_threadpool)

    response = await authorize(db_session, request, "approve", "csrf")

    assert response is expected
    assert "csrf_token" not in request.session


async def test_token_introspection_and_revoke_cache_body_then_threadpool(
    monkeypatch
):
    calls = []

    async def fake_threadpool(func, *args):
        calls.append((func, args))
        return JSONResponse({"ok": True})

    monkeypatch.setattr(oauth2_routes, "run_in_threadpool", fake_threadpool)

    request = make_request(method="POST", body=b"token=abc")

    assert (await token(request)).status_code == HTTPStatus.OK
    assert (await introspect_token(request)).status_code == HTTPStatus.OK
    assert (await revoke_token(request)).status_code == HTTPStatus.OK
    assert calls[0][0] is oauth2_routes._create_token_response_sync
    assert calls[1][0] is oauth2_routes._create_endpoint_response_sync
    assert calls[2][0] is oauth2_routes._create_endpoint_response_sync


def test_oauth_sync_wrappers_remove_session(monkeypatch):
    calls = []
    monkeypatch.setattr(
        oauth2_routes.authorization,
        "create_token_response",
        lambda request: "token-response",
    )
    monkeypatch.setattr(
        oauth2_routes.authorization,
        "create_endpoint_response",
        lambda endpoint, request: f"{endpoint}-response",
    )
    monkeypatch.setattr(
        oauth2_routes, "remove_sync_session", lambda: calls.append(None)
    )

    assert oauth2_routes._create_token_response_sync(  # noqa: PLC2701
        "request"
    ) == "token-response"
    assert oauth2_routes._create_endpoint_response_sync(  # noqa: PLC2701
        "introspection", "request"
    ) == "introspection-response"
    assert calls == [None, None]


def test_authorization_response_sync_handles_approve_and_deny(monkeypatch):
    calls = []

    class FakeAuthorization:
        def validate_consent_request(self, request, end_user):  # noqa: PLR6301
            calls.append(("validate", request, end_user))
            return "grant"

        def create_authorization_response(  # noqa: PLR6301
            self, request, grant_user, grant=None
        ):
            calls.append(("response", grant_user, grant))
            return "auth-response"

    monkeypatch.setattr(oauth2_routes, "authorization", FakeAuthorization())
    monkeypatch.setattr(
        oauth2_routes, "remove_sync_session", lambda: calls.append(None)
    )

    assert oauth2_routes._create_authorization_response_sync(  # noqa: PLC2701
        "request", "user", "approve"
    ) == "auth-response"
    assert oauth2_routes._create_authorization_response_sync(  # noqa: PLC2701
        "request", "user", "deny"
    ) == "auth-response"
    assert ("response", "user", "grant") in calls
    assert ("response", None, None) in calls
    expected_cleanup_calls = 2
    assert calls.count(None) == expected_cleanup_calls


def test_oauth_userinfo_uses_resource_protector(monkeypatch):
    class FakeAcquire:
        def __enter__(self):
            return SimpleNamespace(
                user=SimpleNamespace(
                    id="user-1",
                    email="satoshi@example.com",
                    nickname="Satoshi",
                    lnurl_pubkey="wallet",
                ),
                scope="email profile",
            )

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(
        oauth2_routes.require_oauth,
        "acquire",
        lambda request, scope: FakeAcquire(),
    )
    monkeypatch.setattr(oauth2_routes, "remove_sync_session", lambda: None)

    claims = oauth2_routes._userinfo_sync("request")  # noqa: PLC2701

    assert claims["email"] == "satoshi@example.com"
    assert userinfo("request")["lnurl_pubkey"] == "wallet"


def test_jwks_root_sets_cache_control_header(monkeypatch):
    monkeypatch.setattr(
        oauth2_routes,
        "jwks",
        lambda: {"keys": [{"kid": "key-1"}]},
    )

    response = jwks_root()

    assert response.status_code == HTTPStatus.OK
    assert response.headers["cache-control"].startswith("public, max-age=")
    assert response.body == b'{"keys":[{"kid":"key-1"}]}'


async def test_require_key_admin_rejects_missing_invalid_and_forbidden(
    monkeypatch,
):
    missing_request = make_request()
    missing_request.scope["session"] = {}

    with pytest.raises(HTTPException) as missing_exc:
        await oauth2_routes._require_key_admin(  # noqa: PLC2701
            missing_request
        )
    assert missing_exc.value.status_code == HTTPStatus.UNAUTHORIZED
    assert missing_exc.value.detail == "login_required"

    invalid_request = make_request()
    invalid_request.scope["session"] = {"user_id": "not-a-uuid"}

    with pytest.raises(HTTPException) as invalid_exc:
        await oauth2_routes._require_key_admin(  # noqa: PLC2701
            invalid_request
        )
    assert invalid_exc.value.status_code == HTTPStatus.UNAUTHORIZED
    assert invalid_exc.value.detail == "invalid_session"

    forbidden_request = make_request()
    forbidden_request.scope["session"] = {"user_id": uuid4().hex}

    async def fake_permissions(user_id):
        return set()

    monkeypatch.setattr(
        oauth2_routes, "get_active_user_permissions", fake_permissions
    )

    with pytest.raises(HTTPException) as forbidden_exc:
        await oauth2_routes._require_key_admin(  # noqa: PLC2701
            forbidden_request
        )
    assert forbidden_exc.value.status_code == HTTPStatus.FORBIDDEN
    assert forbidden_exc.value.detail == "forbidden"


async def test_admin_oidc_key_routes_require_admin_and_call_services(
    monkeypatch,
):
    request = make_request()
    request.scope["session"] = {"user_id": uuid4().hex}
    key = SimpleNamespace(
        kid="key-1",
        alg="RS256",
        kty="RSA",
        use="sig",
        status="active",
        backend_reference=None,
        created_at=datetime(2026, 5, 15, tzinfo=UTC),
        activated_at=datetime(2026, 5, 15, tzinfo=UTC),
        validating_since=None,
        retired_at=None,
        retired_after=None,
    )

    async def fake_permissions(user_id):
        return {oauth2_routes.PermissionsEnum.ADMIN}

    async def fake_threadpool(func, *args, **kwargs):
        if func is oauth2_routes.list_signing_keys:
            return [key]
        if func is oauth2_routes.retire_expired_signing_keys:
            return 2
        return key

    monkeypatch.setattr(
        oauth2_routes, "get_active_user_permissions", fake_permissions
    )
    monkeypatch.setattr(oauth2_routes, "run_in_threadpool", fake_threadpool)

    listed = await oauth2_routes.admin_list_oidc_keys(request)
    created = await oauth2_routes.admin_create_oidc_key(request)
    rotated = await oauth2_routes.admin_rotate_oidc_key(request)
    retired = await oauth2_routes.admin_retire_expired_oidc_keys(request)
    activated = await oauth2_routes.admin_activate_oidc_key("key-1", request)

    assert listed["keys"][0]["kid"] == "key-1"
    assert created["kid"] == "key-1"
    assert rotated["status"] == "active"
    assert retired == {"retired": 2}
    assert activated["activated_at"] == "2026-05-15T00:00:00+00:00"


async def test_admin_activate_oidc_key_translates_value_error(monkeypatch):
    request = make_request()
    request.scope["session"] = {"user_id": uuid4().hex}

    async def fake_permissions(user_id):
        return {oauth2_routes.PermissionsEnum.ROOT}

    async def fake_threadpool(func, *args, **kwargs):
        raise ValueError("Unknown OIDC signing key: missing")

    monkeypatch.setattr(
        oauth2_routes, "get_active_user_permissions", fake_permissions
    )
    monkeypatch.setattr(oauth2_routes, "run_in_threadpool", fake_threadpool)

    with pytest.raises(HTTPException) as exc_info:
        await oauth2_routes.admin_activate_oidc_key("missing", request)

    assert exc_info.value.status_code == HTTPStatus.BAD_REQUEST
    assert exc_info.value.detail == "Unknown OIDC signing key: missing"


async def test_admin_rotate_oidc_key_logs_sanitized_failure(
    monkeypatch, caplog
):
    caplog.set_level(logging.ERROR, logger="satoidc.routes.oauth2")
    request = make_request()
    request.scope["session"] = {"user_id": uuid4().hex}

    async def fake_permissions(user_id):
        return {oauth2_routes.PermissionsEnum.ROOT}

    async def fake_threadpool(func, *args, **kwargs):
        raise RuntimeError("private_jwk=secret")

    monkeypatch.setattr(
        oauth2_routes, "get_active_user_permissions", fake_permissions
    )
    monkeypatch.setattr(oauth2_routes, "run_in_threadpool", fake_threadpool)

    with pytest.raises(RuntimeError, match="private_jwk=secret"):
        await oauth2_routes.admin_rotate_oidc_key(request)

    assert any(
        record.event_name == "oidc.key_rotation_failed"
        and record.component == "oauth2"
        and record.reason == "RuntimeError"
        for record in caplog.records
    )
    assert "private_jwk=secret" not in caplog.text


async def _call_admin_oidc_key_route(route_name: str, request: Request):
    if route_name == "create":
        return await oauth2_routes.admin_create_oidc_key(request)
    if route_name == "retire":
        return await oauth2_routes.admin_retire_expired_oidc_keys(request)
    return await oauth2_routes.admin_activate_oidc_key("key-1", request)


@pytest.mark.parametrize(
    ("route_name", "event_name"),
    [
        (
            "create",
            "oidc.key_create_failed",
        ),
        (
            "retire",
            "oidc.key_retire_failed",
        ),
        (
            "activate",
            "oidc.key_activation_failed",
        ),
    ],
)
async def test_admin_oidc_key_operations_log_sanitized_unexpected_failures(
    monkeypatch, caplog, route_name, event_name
):
    caplog.set_level(logging.ERROR, logger="satoidc.routes.oauth2")
    request = make_request()
    request.scope["session"] = {"user_id": uuid4().hex}

    async def fake_permissions(user_id):
        return {oauth2_routes.PermissionsEnum.ROOT}

    async def fake_threadpool(func, *args, **kwargs):
        raise RuntimeError("client_secret=secret")

    monkeypatch.setattr(
        oauth2_routes, "get_active_user_permissions", fake_permissions
    )
    monkeypatch.setattr(oauth2_routes, "run_in_threadpool", fake_threadpool)

    with pytest.raises(RuntimeError, match="client_secret=secret"):
        await _call_admin_oidc_key_route(route_name, request)

    assert any(
        record.event_name == event_name
        and record.component == "oauth2"
        and record.reason == "RuntimeError"
        for record in caplog.records
    )
    assert "client_secret=secret" not in caplog.text
