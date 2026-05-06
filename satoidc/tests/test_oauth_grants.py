import time
from types import SimpleNamespace

from satoidc.auth.oauth2 import IntrospectionEndpoint, RefreshTokenGrant
from satoidc.models import OAuth2Token


class Client:
    def __init__(self, client_id: str):
        self.client_id = client_id

    def get_client_id(self):
        return self.client_id


async def test_refresh_token_grant_accepts_active_refresh_token(
    db_session, make_user
):
    user = await make_user()
    token = OAuth2Token(
        user_id=user.id,
        client_id="client-1",
        token_type="Bearer",
        access_token="access-1",
        refresh_token="refresh-1",
        scope="openid profile",
        issued_at=int(time.time()),
        expires_in=300,
    )
    db_session.add(token)
    await db_session.commit()

    grant = RefreshTokenGrant(SimpleNamespace(), SimpleNamespace())
    stored = grant.authenticate_refresh_token("refresh-1")

    assert RefreshTokenGrant.INCLUDE_NEW_REFRESH_TOKEN is True
    assert "none" in RefreshTokenGrant.TOKEN_ENDPOINT_AUTH_METHODS
    assert stored.refresh_token == "refresh-1"


async def test_refresh_token_grant_revokes_old_refresh_token(
    db_session, make_user
):
    user = await make_user()
    token = OAuth2Token(
        user_id=user.id,
        client_id="client-1",
        token_type="Bearer",
        access_token="access-2",
        refresh_token="refresh-2",
        scope="openid",
        issued_at=int(time.time()),
        expires_in=300,
    )
    db_session.add(token)
    await db_session.commit()

    grant = RefreshTokenGrant(SimpleNamespace(), SimpleNamespace())
    grant.revoke_old_credential(
        grant.authenticate_refresh_token("refresh-2")
    )

    assert grant.authenticate_refresh_token("refresh-2") is None


async def test_introspection_uses_absolute_exp_and_client_permission(
    db_session, make_user
):
    user = await make_user()
    issued_at = int(time.time()) - 30
    token = OAuth2Token(
        user_id=user.id,
        client_id="client-1",
        token_type="Bearer",
        access_token="access-3",
        refresh_token="refresh-3",
        scope="openid email",
        issued_at=issued_at,
        expires_in=300,
    )
    db_session.add(token)
    await db_session.commit()

    endpoint = IntrospectionEndpoint()
    stored = endpoint.query_token("access-3", "access_token")
    payload = endpoint.introspect_token(stored)

    assert endpoint.check_permission(
        stored, Client("client-1"), SimpleNamespace()
    )
    assert not endpoint.check_permission(
        stored, Client("client-2"), SimpleNamespace()
    )
    assert payload["sub"] == str(user.id)
    assert payload["username"] == str(user.id)
    assert payload["exp"] == issued_at + 300
    assert payload["iat"] == issued_at
