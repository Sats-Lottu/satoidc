from http import HTTPStatus
from types import SimpleNamespace
from uuid import uuid4

from authlib.oauth2 import OAuth2Error
from fastapi.responses import JSONResponse
from starlette.requests import Request

import satoidc.routes.oauth2 as oauth2_routes
from satoidc.routes.oauth2 import (
    authorize,
    introspect_token,
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


async def test_authorize_rejects_invalid_csrf(db_session, make_user):
    user = await make_user()
    request = make_request(method="POST")
    request.scope["session"] = {"user_id": user.id.hex, "csrf_token": "good"}

    response = await authorize(db_session, request, "approve", "bad")

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.body == b'{"error":"invalid_csrf"}'


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
