from http import HTTPStatus
from types import SimpleNamespace

import pytest
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import MissingAuthorizationError
from fastapi import HTTPException
from starlette.requests import Request

from satoidc.fastapi_oauth2.authorization_server import (
    AuthorizationServer,
    create_bearer_token_generator,
    create_token_expires_in_generator,
    create_token_generator,
    import_string,
)
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


def test_oauth2_payload_handles_empty_and_list_json_values():
    request = _request(
        method="POST",
        body=b'{"scope": ["openid", "email"], "empty": []}',
        content_type="application/json",
    )

    oauth_request = FastAPIOAuth2Request(request)

    assert oauth_request.data["scope"] == "openid"
    assert oauth_request.datalist["scope"] == ["openid", "email"]
    assert oauth_request.data["empty"] is None


def test_json_payload_ignores_non_json_content_type():
    request = _request(method="POST", body=b'{"token": "abc"}')

    json_request = FastAPIJsonRequest(request)

    assert json_request.payload.data == {}


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


def test_resource_protector_decorator_runs_after_token_validation():
    class ValidProtector(ResourceProtector):
        def validate_request(self, scope, request):  # noqa: PLR6301
            return SimpleNamespace(access_token="token-1")

    protector = ValidProtector()

    @protector("profile")
    def endpoint(request):
        return request.state.token.access_token

    assert endpoint(_request()) == "token-1"


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


def test_resource_protector_context_and_decorator_error_paths():
    class MissingAuthProtector(ResourceProtector):
        def validate_request(self, scope, request):  # noqa: PLR6301
            raise MissingAuthorizationError()

    request = _request()
    protector = MissingAuthProtector()

    with pytest.raises(HTTPException):
        with protector.acquire(request, "profile"):
            raise AssertionError("context body should not run")

    @protector("profile", optional=True)
    def optional_endpoint(request):
        return "anonymous"

    @protector("profile")
    def required_endpoint(request):
        return "authenticated"

    assert optional_endpoint(request) == "anonymous"
    with pytest.raises(HTTPException):
        required_endpoint(request)


def test_resource_protector_decorator_translates_oauth_error():
    class InvalidTokenProtector(ResourceProtector):
        def validate_request(self, scope, request):  # noqa: PLR6301
            raise OAuth2Error(error="invalid_token", status_code=401)

    protector = InvalidTokenProtector()

    @protector("profile")
    def endpoint(request):
        return "ok"

    with pytest.raises(HTTPException) as exc_info:
        endpoint(_request())

    assert exc_info.value.status_code == HTTPStatus.UNAUTHORIZED


def test_authorization_server_helpers_and_response_handling(tmp_path):
    metadata_file = tmp_path / "metadata.json"
    metadata_file.write_text(
        """{
          "issuer": "https://issuer.example",
          "authorization_endpoint": "https://issuer.example/authorize",
          "token_endpoint": "https://issuer.example/token",
          "response_types_supported": ["code"]
        }""",
        encoding="utf-8",
    )
    app = SimpleNamespace(
        config={
            "OAUTH2_METADATA_FILE": str(metadata_file),
            "OAUTH2_ERROR_URIS": [
                ("invalid_client", "https://issuer.example/errors")
            ],
            "OAUTH2_TOKEN_EXPIRES_IN": {"authorization_code": 123},
            "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
        }
    )

    server = AuthorizationServer(
        app,
        query_client=lambda client_id: f"client:{client_id}",
        save_token=lambda token, request: ("saved", token),
    )
    error = SimpleNamespace(error="invalid_client")
    response = server.handle_response(200, {"ok": True}, [])

    assert import_string("json.loads") is not None
    assert server.query_client("abc") == "client:abc"
    assert server.save_token({"access_token": "abc"}, None) == (
        "saved",
        {"access_token": "abc"},
    )
    assert server.get_error_uri(None, error) == "https://issuer.example/errors"
    assert server.create_oauth2_request(_request()).method == "GET"
    assert server.create_json_request(_request()).payload.data == {}
    assert response.status_code == HTTPStatus.OK
    assert response.headers["content-type"] == "application/json"
    assert server.metadata["issuer"] == "https://issuer.example"


def test_authorization_server_validate_consent_request_sets_prompt():
    class Grant:
        def __init__(self):
            self.validated = False

        def validate_consent_request(self):
            self.validated = True

    class ConsentServer(AuthorizationServer):
        def __init__(self):
            super().__init__()
            self.grant = Grant()

        def get_authorization_grant(self, request):  # noqa: PLR6301
            self.recorded_request = request
            return self.grant

    server = ConsentServer()
    request = _request()

    grant = server.validate_consent_request(request, end_user="user-1")
    server.send_signal("ignored")

    assert grant is server.grant
    assert grant.validated is True
    assert grant.prompt is None
    assert server.recorded_request.user == "user-1"


def test_token_generator_variants():
    token_length = 8
    configured_expires_in = 99

    def custom_token(*args, **kwargs):
        return "custom-token"

    expires_in = create_token_expires_in_generator(
        {
            "OAUTH2_TOKEN_EXPIRES_IN": {
                "client_credentials": configured_expires_in
            }
        }
    )
    bearer = create_bearer_token_generator(
        {"OAUTH2_REFRESH_TOKEN_GENERATOR": False}
    )

    assert create_token_generator(custom_token)() == "custom-token"
    assert create_token_generator("json.dumps")({"a": 1}) == '{"a": 1}'
    assert len(create_token_generator(True, token_length)()) >= token_length
    assert create_token_generator(False) is None
    assert expires_in(None, "client_credentials") == configured_expires_in
    assert expires_in(None, "unknown") > 0
    assert bearer.refresh_token_generator is None
