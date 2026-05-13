import pytest

from satoidc.routes.create_client import (
    ClientMetadataValidationError,
    build_client_metadata,
    parse_multiline_values,
)


def test_parse_multiline_values_trims_blank_lines():
    assert parse_multiline_values(" code \n\n refresh_token \n") == [
        "code",
        "refresh_token",
    ]


def test_build_client_metadata_normalizes_valid_values():
    metadata = build_client_metadata(
        client_name=" Example App ",
        client_uri="https://client.example",
        scope="openid profile profile",
        redirect_uri="https://client.example/callback\n",
        grant_type="authorization_code\nrefresh_token",
        response_type="code",
        token_endpoint_auth_method="client_secret_post",
    )

    assert metadata == {
        "client_name": "Example App",
        "client_uri": "https://client.example",
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": ["https://client.example/callback"],
        "response_types": ["code"],
        "scope": "openid profile",
        "token_endpoint_auth_method": "client_secret_post",
    }


def test_build_client_metadata_rejects_invalid_values():
    with pytest.raises(ClientMetadataValidationError) as exc_info:
        build_client_metadata(
            client_name="",
            client_uri="not-a-url",
            scope="openid admin",
            redirect_uri="javascript:alert(1)",
            grant_type="client_credentials",
            response_type="token",
            token_endpoint_auth_method="private_key_jwt",
        )

    assert "Client name is required." in exc_info.value.messages
    assert "Client URI must be an absolute HTTP(S) URL." in (
        exc_info.value.messages
    )
    assert "Unsupported scopes: admin" in exc_info.value.messages
    assert "Unsupported grant types: client_credentials" in (
        exc_info.value.messages
    )
    assert "Unsupported response types: token" in exc_info.value.messages
    assert "Unsupported token endpoint auth method: private_key_jwt" in (
        exc_info.value.messages
    )
