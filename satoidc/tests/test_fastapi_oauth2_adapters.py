from http import HTTPStatus
from types import SimpleNamespace

import pytest
from authlib.oauth2 import OAuth2Error
from fastapi import HTTPException
from starlette.requests import Request

from satoidc.fastapi_oauth2.requests import (
    FastAPIJsonRequest,
    FastAPIOAuth2Request,
)
from satoidc.fastapi_oauth2.resource_protector import (
    ResourceProtector,
    raise_error_response,
)


def _request(
    *,
    method: str = "GET",
    path: str = "/oauth/token",
    query_string: bytes = b"",
    body: bytes = b"",
    content_type: str | None = None,
) -> Request:
    headers = []
    if content_type:
        headers.append((b"content-type", content_type.encode()))

    request = Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "query_string": query_string,
            "headers": headers,
            "server": ("testserver", 80),
            "scheme": "https",
            "client": ("testclient", 50000),
            "state": {},
        }
    )
    request._body = body
    return request


def test_oauth2_request_reads_query_and_cached_form_body():
    request = _request(
        method="POST",
        query_string=b"scope=openid&scope=email&client_id=query-client",
        body=b"client_id=form-client&grant_type=authorization_code",
        content_type="application/x-www-form-urlencoded",
    )

    oauth_request = FastAPIOAuth2Request(request)

    assert oauth_request.method == "POST"
    assert oauth_request.args["client_id"] == "query-client"
    assert oauth_request.form["client_id"] == "form-client"
    assert oauth_request.data["grant_type"] == "authorization_code"
    assert oauth_request.datalist["scope"] == ["openid", "email"]


def test_oauth2_request_reads_cached_json_body():
    request = _request(
        method="POST",
        body=b'{"token": "abc", "token_type_hint": "access_token"}',
        content_type="application/json",
    )

    oauth_request = FastAPIOAuth2Request(request)

    assert oauth_request.data == {
        "token": "abc",
        "token_type_hint": "access_token",
    }
    assert oauth_request.datalist["token"] == ["abc"]


def test_json_request_ignores_invalid_or_non_object_json():
    invalid_request = FastAPIJsonRequest(
        _request(
            method="POST",
            body=b"{invalid",
            content_type="application/json",
        )
    )
    list_request = FastAPIJsonRequest(
        _request(
            method="POST",
            body=b'["not", "an", "object"]',
            content_type="application/json",
        )
    )

    assert invalid_request.payload.data == {}
    assert list_request.payload.data == {}


def test_resource_protector_uses_fastapi_request_adapter():
    class RecordingProtector(ResourceProtector):
        def validate_request(self, scope, request):
            self.recorded_scope = scope
            self.recorded_request = request
            return SimpleNamespace(access_token="token-1")

    request = _request(
        method="GET",
        query_string=b"access_token=token-1",
    )
    protector = RecordingProtector()

    token = protector.acquire_token(request, "profile")

    assert token.access_token == "token-1"
    assert request.state.token is token
    assert protector.recorded_scope == "profile"
    assert isinstance(protector.recorded_request, FastAPIOAuth2Request)
    assert protector.recorded_request.data["access_token"] == "token-1"


def test_resource_protector_translates_oauth_errors():
    error = OAuth2Error(
        error="invalid_token",
        description="Token is invalid",
        status_code=401,
    )

    with pytest.raises(HTTPException) as exc_info:
        raise_error_response(error)

    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED
    assert exc_info.value.detail["error"] == "invalid_token"
