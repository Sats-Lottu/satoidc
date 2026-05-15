from uuid import UUID

import pytest

from satoidc.auth.client_management import (
    CLIENT_DISABLED_AT,
    CLIENT_SECRET_ROTATED_AT,
    is_client_disabled,
    rotate_client_secret,
    set_client_disabled,
)
from satoidc.models import OAuth2Client
from satoidc.routes.create_client import (
    ClientMetadataValidationError,
    build_client_metadata,
    parse_multiline_values,
    update_client_metadata,
)

USER_ID = UUID("00000000-0000-0000-0000-000000000001")
DISABLED_AT = 10
ROTATED_AT = 11
UPDATED_AT = 12
ENABLE_UPDATED_AT = 21
ROTATE_UPDATED_AT = 30


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


def test_build_client_metadata_rejects_missing_required_lists():
    with pytest.raises(ClientMetadataValidationError) as exc_info:
        build_client_metadata(
            client_name="Client",
            client_uri="",
            scope="",
            redirect_uri="",
            grant_type="",
            response_type="",
            token_endpoint_auth_method=None,
        )

    assert exc_info.value.messages == [
        "At least one redirect URI is required.",
        "At least one grant type is required.",
        "At least one response type is required.",
        "At least one scope is required.",
    ]


def test_build_client_metadata_requires_code_grant_for_code_response():
    with pytest.raises(ClientMetadataValidationError) as exc_info:
        build_client_metadata(
            client_name="Client",
            client_uri="",
            scope="openid",
            redirect_uri="https://client.example/callback",
            grant_type="refresh_token",
            response_type="code",
            token_endpoint_auth_method="client_secret_basic",
        )

    assert exc_info.value.messages == [
        "The code response type requires the authorization_code grant."
    ]


def test_update_client_metadata_preserves_management_state():
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="client-id",
        client_id_issued_at=1,
        client_secret="secret",
    )
    client.set_client_metadata(
        {
            "client_name": "Old",
            CLIENT_DISABLED_AT: DISABLED_AT,
            CLIENT_SECRET_ROTATED_AT: ROTATED_AT,
        }
    )

    metadata = update_client_metadata(
        client,
        client_name=" New ",
        client_uri="https://client.example",
        scope="openid email",
        redirect_uri="https://client.example/callback",
        grant_type="authorization_code",
        response_type="code",
        token_endpoint_auth_method="client_secret_basic",
        now=UPDATED_AT,
    )

    assert metadata["client_name"] == "New"
    assert metadata[CLIENT_DISABLED_AT] == DISABLED_AT
    assert metadata[CLIENT_SECRET_ROTATED_AT] == ROTATED_AT
    assert metadata["updated_at"] == UPDATED_AT


def test_update_client_metadata_skips_falsey_management_state():
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="client-id",
        client_id_issued_at=1,
        client_secret="secret",
    )
    client.set_client_metadata(
        {
            "client_name": "Old",
            CLIENT_DISABLED_AT: 0,
            CLIENT_SECRET_ROTATED_AT: None,
        }
    )

    metadata = update_client_metadata(
        client,
        client_name="New",
        client_uri="",
        scope="openid",
        redirect_uri="https://client.example/callback",
        grant_type="authorization_code",
        response_type="code",
        token_endpoint_auth_method="client_secret_basic",
        now=UPDATED_AT,
    )

    assert CLIENT_DISABLED_AT not in metadata
    assert CLIENT_SECRET_ROTATED_AT not in metadata


def test_set_client_disabled_toggles_metadata_state():
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="client-id",
        client_id_issued_at=1,
        client_secret="secret",
    )
    client.set_client_metadata({"client_name": "Client"})

    set_client_disabled(client, disabled=True, now=DISABLED_AT)
    assert is_client_disabled(client)
    assert client.client_metadata[CLIENT_DISABLED_AT] == DISABLED_AT

    set_client_disabled(client, disabled=False, now=ENABLE_UPDATED_AT)
    assert not is_client_disabled(client)
    assert CLIENT_DISABLED_AT not in client.client_metadata
    assert client.client_metadata["updated_at"] == ENABLE_UPDATED_AT


def test_rotate_client_secret_updates_secret_once():
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="client-id",
        client_id_issued_at=1,
        client_secret="old-secret",
    )
    client.set_client_metadata(
        {"token_endpoint_auth_method": "client_secret_post"}
    )

    secret = rotate_client_secret(client, now=ROTATE_UPDATED_AT)

    assert secret
    assert secret != "old-secret"
    assert client.client_secret == secret
    assert client.client_metadata[CLIENT_SECRET_ROTATED_AT] == (
        ROTATE_UPDATED_AT
    )


def test_rotate_client_secret_rejects_public_client():
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="client-id",
        client_id_issued_at=1,
        client_secret="",
    )
    client.set_client_metadata({"token_endpoint_auth_method": "none"})

    with pytest.raises(ClientMetadataValidationError):
        rotate_client_secret(client)
