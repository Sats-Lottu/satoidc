from datetime import datetime, timezone

from sqlalchemy import select

from satoidc.enums import PermissionsEnum
from satoidc.models import (
    LnurlAuthChallenge,
    OAuth2Client,
    Permission,
    User,
)


async def test_user_permission_and_challenge_persist_with_real_database(
    db_session,
):
    user = User(
        lnurl_pubkey=None,
        email="root@example.com",
        login="rootuser",
        password_hash="hash",
        nickname="Root",
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    permission = Permission(
        user_id=user.id,
        granted_by=None,
        permission_type=PermissionsEnum.ROOT,
        expiration_date=None,
        reason="test root user",
    )
    challenge = LnurlAuthChallenge(user_id=user.id, action="login")
    db_session.add_all([permission, challenge])
    await db_session.commit()

    stored_user = await db_session.scalar(
        select(User).where(User.login == "rootuser")
    )
    stored_permission = await db_session.scalar(
        select(Permission).where(Permission.user_id == user.id)
    )
    stored_challenge = await db_session.scalar(
        select(LnurlAuthChallenge).where(
            LnurlAuthChallenge.k1 == challenge.k1
        )
    )

    assert stored_user is not None
    assert stored_user.get_user_id() == stored_user.id
    assert stored_permission.permission_type == PermissionsEnum.ROOT
    assert stored_challenge.action == "login"
    assert stored_challenge.consumed is False
    assert isinstance(stored_challenge.created_at, datetime)
    assert stored_challenge.created_at.tzinfo is not None or timezone.utc


async def test_oauth_client_metadata_round_trips_in_real_database(
    db_session, make_user
):
    user = await make_user()
    client = OAuth2Client(
        user_id=user.id,
        client_id="client-id",
        client_id_issued_at=1,
        client_secret="secret",
    )
    client.set_client_metadata(
        {
            "client_name": "Test Client",
            "redirect_uris": ["http://localhost:8001/auth/callback"],
            "scope": "openid email profile",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }
    )
    db_session.add(client)
    await db_session.commit()

    stored_client = await db_session.scalar(
        select(OAuth2Client).where(OAuth2Client.client_id == "client-id")
    )

    assert stored_client.client_name == "Test Client"
    assert stored_client.check_redirect_uri(
        "http://localhost:8001/auth/callback"
    )
    assert stored_client.check_response_type("code")
    assert stored_client.check_grant_type("authorization_code")
