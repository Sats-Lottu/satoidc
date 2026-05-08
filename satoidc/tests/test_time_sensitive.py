from datetime import datetime, timedelta, timezone
from uuid import UUID

from freezegun import freeze_time
from sqlalchemy import select

from satoidc.models import (
    LnurlAuthChallenge,
    OAuth2AuthorizationCode,
    OAuth2Token,
)
from satoidc.routes.lnurl_auth import lnurl_auth_callback
from satoidc.schemas.lnurl import LnurlAuthCallbackIn
from satoidc.settings import ENV


@freeze_time("2026-05-06T10:00:00Z")
def test_authorization_code_expires_after_five_minutes():
    now = datetime(2026, 5, 6, 10, 0, tzinfo=timezone.utc)
    code = OAuth2AuthorizationCode(
        code="auth-code",
        client_id="client-1",
        redirect_uri="http://localhost/callback",
        scope="openid",
        user_id=UUID("00000000-0000-0000-0000-000000000001"),
        auth_time=int(now.timestamp()) - 301,
    )

    assert code.is_expired() is True


@freeze_time("2026-05-06T10:00:00Z")
def test_authorization_code_is_valid_at_expiration_boundary():
    now = datetime(2026, 5, 6, 10, 0, tzinfo=timezone.utc)
    code = OAuth2AuthorizationCode(
        code="auth-code",
        client_id="client-1",
        redirect_uri="http://localhost/callback",
        scope="openid",
        user_id=UUID("00000000-0000-0000-0000-000000000001"),
        auth_time=int(now.timestamp()) - 300,
    )

    assert code.is_expired() is False


@freeze_time("2026-05-06T10:00:00Z")
def test_refresh_token_active_window_depends_on_issued_at_and_ttl():
    now = datetime(2026, 5, 6, 10, 0, tzinfo=timezone.utc)
    issued_at = int(now.timestamp())
    token = OAuth2Token(
        user_id=UUID("00000000-0000-0000-0000-000000000001"),
        client_id="client-1",
        token_type="Bearer",
        access_token="access-token",
        refresh_token="refresh-token",
        issued_at=issued_at,
        expires_in=300,
    )

    assert token.is_refresh_token_active() is True

    with freeze_time("2026-05-06T10:10:01Z"):
        assert token.is_refresh_token_active() is False


@freeze_time("2026-05-06T10:00:00Z")
def test_revoked_refresh_token_is_inactive_even_before_expiration():
    token = OAuth2Token(
        user_id=UUID("00000000-0000-0000-0000-000000000001"),
        client_id="client-1",
        token_type="Bearer",
        access_token="access-token",
        refresh_token="refresh-token",
        issued_at=int(
            datetime(2026, 5, 6, 10, 0, tzinfo=timezone.utc).timestamp()
        ),
        expires_in=300,
        refresh_token_revoked_at=int(
            datetime(2026, 5, 6, 10, 0, 1, tzinfo=timezone.utc).timestamp()
        ),
    )

    assert token.is_refresh_token_active() is False


async def test_expired_lnurl_challenge_is_rejected(db_session, make_user):
    now = datetime(2026, 5, 6, 10, 0, tzinfo=timezone.utc)
    expired_at = now - timedelta(seconds=ENV.LNURL_K1_TTL_SECONDS + 1)
    wallet_key = "02" + "1" * 64
    user = await make_user(lnurl_pubkey=wallet_key)
    challenge = LnurlAuthChallenge(
        k1="3" * 64,
        action="login",
        user_id=user.id,
    )
    db_session.add(challenge)
    await db_session.commit()

    challenge.created_at = expired_at
    await db_session.commit()

    with freeze_time(now):
        response = await lnurl_auth_callback(
            LnurlAuthCallbackIn(
                k1=challenge.k1,
                key=wallet_key,
                sig="0" * 16,
                action="login",
            ),
            db_session,
        )

    stored_challenge = await db_session.scalar(
        select(LnurlAuthChallenge).where(
            LnurlAuthChallenge.k1 == challenge.k1
        )
    )
    assert response == {
        "status": "ERROR",
        "reason": "Invalid or expired k1",
    }
    assert stored_challenge.verified is False
