import time
from types import SimpleNamespace

from satoidc.auth.oauth2 import (
    AuthorizationCodeGrant,
    IntrospectionEndpoint,
    OpenIDCode,
    RefreshTokenGrant,
    exists_nonce,
)
from satoidc.models import OAuth2AuthorizationCode, OAuth2Token


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


async def test_authorization_code_grant_persists_queries_and_deletes_code(
    db_session, make_user
):
    user = await make_user()
    grant = AuthorizationCodeGrant(SimpleNamespace(), SimpleNamespace())
    grant.request.client = SimpleNamespace(client_id="client-1")
    request = SimpleNamespace(
        payload=SimpleNamespace(
            data={
                "nonce": "nonce-1",
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
            },
            client_id="client-1",
            redirect_uri="https://client.example/callback",
            scope="openid profile",
        ),
        user=user,
    )

    code = grant.generate_authorization_code()
    auth_code = grant.save_authorization_code(code, request)
    stored = grant.query_authorization_code(code, grant.client)
    minimum_urlsafe_token_length = 64

    assert len(code) > minimum_urlsafe_token_length
    assert auth_code.code == code
    assert stored.code_challenge == "challenge"
    assert exists_nonce("nonce-1", request) is True
    assert grant.authenticate_user(stored).id == user.id

    grant.delete_authorization_code(stored)

    assert grant.query_authorization_code(code, grant.client) is None


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


async def test_grants_ignore_expired_or_unknown_credentials(
    db_session, make_user
):
    user = await make_user()
    expired_code = OAuth2AuthorizationCode(
        code="expired-code",
        client_id="client-1",
        redirect_uri="https://client.example/callback",
        scope="openid",
        user_id=user.id,
        auth_time=int(time.time()) - 301,
    )
    db_session.add(expired_code)
    await db_session.commit()

    code_grant = AuthorizationCodeGrant(SimpleNamespace(), SimpleNamespace())
    refresh_grant = RefreshTokenGrant(SimpleNamespace(), SimpleNamespace())

    assert code_grant.query_authorization_code(
        "expired-code", Client("client-1")
    ) is None
    assert refresh_grant.authenticate_refresh_token("missing") is None


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


async def test_refresh_grant_and_introspection_cover_refresh_hint(
    db_session, make_user
):
    user = await make_user()
    token = OAuth2Token(
        user_id=user.id,
        client_id="client-1",
        token_type="Bearer",
        access_token="access-4",
        refresh_token="refresh-4",
        scope="openid",
        issued_at=int(time.time()),
        expires_in=300,
    )
    db_session.add(token)
    await db_session.commit()

    refresh_grant = RefreshTokenGrant(SimpleNamespace(), SimpleNamespace())
    endpoint = IntrospectionEndpoint()

    assert refresh_grant.authenticate_user(token).id == user.id
    assert endpoint.query_token("refresh-4", "refresh_token").id == token.id
    assert endpoint.query_token("refresh-4", None).id == token.id


def test_openid_code_delegates_public_key_claim_header_and_userinfo(
    db_session,
):
    request = SimpleNamespace(payload=SimpleNamespace(client_id="client-x"))
    openid = OpenIDCode(require_nonce=True)
    user = SimpleNamespace(
        id="user-1",
        email="satoshi@example.com",
        nickname="Satoshi",
        lnurl_pubkey="wallet-key",
    )

    assert openid.exists_nonce("nonce-x", request) is False
    assert openid.get_client_algorithm(Client("client-x")) == "RS256"
    assert openid.get_client_claims(Client("client-x"))["iss"] == (
        "http://localhost:8000"
    )
    header = openid.get_encode_header(Client("client-x"))
    assert header["alg"] == "RS256"
    assert header["typ"] == "JWT"
    assert "kid" in header
    assert openid.resolve_client_private_key(Client("client-x")) is not None
    assert openid.generate_user_info(user, "email profile")["email"] == (
        "satoshi@example.com"
    )
