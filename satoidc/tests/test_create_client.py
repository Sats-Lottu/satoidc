import logging
from http import HTTPStatus
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import select

from satoidc.auth.client_management import (
    CLIENT_DISABLED_AT,
    CLIENT_SECRET_ROTATED_AT,
    ClientMetadataValidationError,
    is_client_disabled,
    rotate_client_secret,
    set_client_disabled,
)
from satoidc.enums import PermissionsEnum
from satoidc.models import OAuth2Client, Permission
from satoidc.routes.create_client import create_client_command
from satoidc.schemas.oauth_clients import CreateOAuthClientCommand
from satoidc.services.oauth_clients import (
    build_client_metadata,
    create_oauth_client,
    delete_oauth_client,
    parse_multiline_values,
    rotate_oauth_client_secret,
    toggle_oauth_client_status,
    update_client_metadata,
    update_oauth_client,
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


def test_rotate_client_secret_rejects_public_client(
    caplog, assert_no_sensitive_log_values
):
    caplog.set_level(logging.INFO, logger="satoidc.auth.client_management")
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="client-id",
        client_id_issued_at=1,
        client_secret="client-secret-value",
    )
    client.set_client_metadata({"token_endpoint_auth_method": "none"})

    with pytest.raises(ClientMetadataValidationError):
        rotate_client_secret(client)
    assert any(
        record.event_name == "client.secret_rotation_failed"
        and record.component == "client_management"
        and record.reason == "public_client"
        for record in caplog.records
    )
    assert_no_sensitive_log_values("old-secret")


async def test_create_oauth_client_persists_confidential_client(db_session):
    client, secret = await create_oauth_client(
        db_session,
        user_id=USER_ID,
        client_name="Client",
        client_uri="https://client.example",
        scope="openid profile",
        redirect_uri="https://client.example/callback",
        grant_type="authorization_code",
        response_type="code",
        token_endpoint_auth_method="client_secret_basic",
    )

    stored = await db_session.get(OAuth2Client, client.id)
    assert stored is not None
    assert secret
    assert stored.client_secret == secret
    assert stored.client_metadata["client_name"] == "Client"


async def test_create_client_command_persists_guided_form_client(
    db_session, make_user
):
    user = await make_user(login="command_user", email="command@example.com")
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.DEVELOPER,
            expiration_date=None,
            reason="test developer access",
        )
    )
    await db_session.commit()
    request = SimpleNamespace(session={"user_id": user.id.hex})

    response = await create_client_command(
        db_session,
        request,
        CreateOAuthClientCommand(
            client_name="Command Client",
            client_uri="https://command.example",
            redirect_uri="https://command.example/callback",
            profile_scope=True,
            email_scope=False,
            refresh_token_enabled=True,
        ),
    )

    clients = (
        await db_session.scalars(
            select(OAuth2Client).where(OAuth2Client.user_id == user.id)
        )
    ).all()
    client = next(
        item
        for item in clients
        if item.client_metadata["client_name"] == "Command Client"
    )
    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/create_client"
    assert client is not None
    assert client.client_metadata["scope"] == "openid profile"
    assert client.client_metadata["grant_types"] == [
        "authorization_code",
        "refresh_token",
    ]
    assert request.session["create_client_flash"]["type"] == "created"
    assert request.session["create_client_flash"]["client_secret"]


async def test_create_client_command_rejects_missing_permission(
    db_session, make_user
):
    user = await make_user(login="plain_user", email="plain@example.com")
    request = SimpleNamespace(session={"user_id": user.id.hex})

    response = await create_client_command(
        db_session,
        request,
        CreateOAuthClientCommand(
            client_name="Command Client",
            client_uri="https://command.example",
            redirect_uri="https://command.example/callback",
        ),
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/forbidden"


async def test_update_oauth_client_generates_secret_for_private_method(
    db_session,
):
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="public-client",
        client_id_issued_at=1,
        client_secret="",
    )
    client.set_client_metadata({"token_endpoint_auth_method": "none"})
    db_session.add(client)
    await db_session.commit()

    generated_secret = await update_oauth_client(
        db_session,
        client,
        client_name="Client",
        client_uri="https://client.example",
        scope="openid",
        redirect_uri="https://client.example/callback",
        grant_type="authorization_code",
        response_type="code",
        token_endpoint_auth_method="client_secret_post",
    )

    assert generated_secret
    assert client.client_secret == generated_secret
    assert client.client_metadata["token_endpoint_auth_method"] == (
        "client_secret_post"
    )


async def test_update_oauth_client_clears_secret_for_public_method(
    db_session,
):
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="confidential-client",
        client_id_issued_at=1,
        client_secret="old-secret",
    )
    client.set_client_metadata(
        {"token_endpoint_auth_method": "client_secret_basic"}
    )
    db_session.add(client)
    await db_session.commit()

    generated_secret = await update_oauth_client(
        db_session,
        client,
        client_name="Client",
        client_uri="https://client.example",
        scope="openid",
        redirect_uri="https://client.example/callback",
        grant_type="authorization_code",
        response_type="code",
        token_endpoint_auth_method="none",
    )

    assert generated_secret is None
    assert not client.client_secret
    assert client.client_metadata["token_endpoint_auth_method"] == "none"


async def test_client_management_services_persist_mutations(db_session):
    client = OAuth2Client(
        user_id=USER_ID,
        client_id="managed-client",
        client_id_issued_at=1,
        client_secret="old-secret",
    )
    client.set_client_metadata(
        {"token_endpoint_auth_method": "client_secret_basic"}
    )
    db_session.add(client)
    await db_session.commit()

    secret = await rotate_oauth_client_secret(db_session, client)
    assert secret != "old-secret"
    assert client.client_secret == secret

    await toggle_oauth_client_status(db_session, client)
    assert is_client_disabled(client)

    await delete_oauth_client(db_session, client)
    assert await db_session.get(OAuth2Client, client.id) is None
