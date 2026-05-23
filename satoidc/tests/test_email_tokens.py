from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import pytest
from sqlalchemy import select

import satoidc.services.email_tokens as email_tokens_module
from satoidc.auth.security import hash_password, verify_password
from satoidc.models import EmailToken, User
from satoidc.services.email_delivery import EmailDeliveryError
from satoidc.services.email_tokens import (
    RECOVERY_REQUEST_MESSAGE,
    RESET_PASSWORD,
    VERIFY_EMAIL,
    EmailTokenError,
    EmailTokenRateLimited,
    build_email_url,
    hash_email_token,
    invalidate_password_reset_tokens,
    issue_email_token,
    public_base_url,
    request_email_verification,
    request_password_reset,
    reset_password_with_token,
    verify_email_token,
)


@pytest.fixture
def disable_email_token_rate_limit(monkeypatch):
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        0,
    )


async def test_issue_email_token_stores_only_hash(
    db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(email="satoshi@example.com")

    email_token, raw_token = await issue_email_token(
        db_session, user, purpose=VERIFY_EMAIL
    )

    assert raw_token
    assert email_token.token_hash == hash_email_token(raw_token)
    assert raw_token not in email_token.token_hash


async def test_issue_email_token_rejects_missing_email(db_session, make_user):
    user = await make_user(email=None)

    with pytest.raises(EmailTokenError, match="No email"):
        await issue_email_token(db_session, user, purpose=VERIFY_EMAIL)


async def test_issue_email_token_rate_limits_recent_active_token(
    db_session, make_user
):
    user = await make_user(email="limited@example.com")
    issued_at = datetime(2026, 5, 23, tzinfo=UTC)

    await issue_email_token(
        db_session,
        user,
        purpose=VERIFY_EMAIL,
        now=issued_at,
    )

    with pytest.raises(EmailTokenRateLimited):
        await issue_email_token(
            db_session,
            user,
            purpose=VERIFY_EMAIL,
            now=issued_at + timedelta(seconds=1),
        )


def test_email_url_helpers_use_configured_and_request_base_urls(monkeypatch):
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_PUBLIC_BASE_URL",
        "",
    )
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "OAUTH2_JWT_ISS",
        "https://issuer.example/",
    )

    assert public_base_url("https://request.example/") == (
        "https://request.example"
    )
    assert build_email_url(
        "/verify-email",
        "token value",
        request_base_url="https://request.example/",
    ) == (
        "https://request.example/verify-email?token=token+value"
    )

    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_PUBLIC_BASE_URL",
        "https://mail.example/",
    )
    assert public_base_url("https://request.example/") == (
        "https://mail.example"
    )


async def test_verify_email_token_marks_email_verified_once(
    db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(email="satoshi@example.com")
    _, raw_token = await issue_email_token(
        db_session, user, purpose=VERIFY_EMAIL
    )

    verified_user = await verify_email_token(db_session, raw_token)

    assert verified_user.email_verified is True
    assert verified_user.email_verified_at is not None
    with pytest.raises(EmailTokenError):
        await verify_email_token(db_session, raw_token)


async def test_verify_email_token_rejects_missing_token(db_session):
    with pytest.raises(EmailTokenError, match="Invalid or expired"):
        await verify_email_token(db_session, None)


async def test_request_email_verification_rejects_invalid_account_states(
    db_session, make_user
):
    no_email = await make_user(login="noemail", email=None)
    verified = await make_user(
        login="verified-email",
        email="verified-email@example.com",
    )
    verified.email_verified = True
    db_session.add(verified)
    await db_session.commit()

    with pytest.raises(EmailTokenError, match="No email"):
        await request_email_verification(db_session, no_email)
    with pytest.raises(EmailTokenError, match="already verified"):
        await request_email_verification(db_session, verified)


async def test_verify_email_token_rejects_old_email(
    db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(email="old@example.com")
    _, raw_token = await issue_email_token(
        db_session, user, purpose=VERIFY_EMAIL
    )
    user.email = "new@example.com"
    db_session.add(user)
    await db_session.commit()

    with pytest.raises(EmailTokenError):
        await verify_email_token(db_session, raw_token)

    assert user.email_verified is False


async def test_request_password_reset_is_enumeration_resistant(
    db_session, make_user, monkeypatch
):
    sent_urls = []

    async def send_password_reset(user, email, reset_url):
        sent_urls.append(reset_url)

    monkeypatch.setattr(
        "satoidc.services.email_tokens.send_password_reset",
        send_password_reset,
    )
    unverified_user = await make_user(
        login="unverified",
        email="unverified@example.com",
    )
    verified_user = await make_user(
        login="verified",
        email="verified@example.com",
    )
    verified_user.email_verified = True
    db_session.add(verified_user)
    await db_session.commit()

    unknown_message = await request_password_reset(
        db_session, "unknown@example.com"
    )
    unverified_message = await request_password_reset(
        db_session, unverified_user.email
    )
    verified_message = await request_password_reset(
        db_session,
        verified_user.email,
        request_base_url="https://id.example/",
    )

    reset_tokens = (
        await db_session.scalars(
            select(EmailToken).where(EmailToken.purpose == RESET_PASSWORD)
        )
    ).all()
    assert unknown_message == unverified_message == verified_message
    assert len(reset_tokens) == 1
    assert sent_urls
    assert sent_urls[0].startswith(
        "https://id.example/reset-password?token="
    )


async def test_request_password_reset_handles_invalid_and_rate_limited_email(
    db_session, make_user
):
    user = await make_user(email="limited-reset@example.com")
    user.email_verified = True
    db_session.add(user)
    await db_session.commit()
    await issue_email_token(db_session, user, purpose=RESET_PASSWORD)

    invalid_message = await request_password_reset(db_session, "not-email")
    limited_message = await request_password_reset(db_session, user.email)

    assert invalid_message == RECOVERY_REQUEST_MESSAGE
    assert limited_message == RECOVERY_REQUEST_MESSAGE


async def test_reset_password_with_token_consumes_all_active_reset_tokens(
    db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(
        email="verified@example.com",
        password_hash=hash_password("OldStrong1!"),
    )
    user.email_verified = True
    db_session.add(user)
    await db_session.commit()
    _, first_token = await issue_email_token(
        db_session, user, purpose=RESET_PASSWORD
    )
    await issue_email_token(db_session, user, purpose=RESET_PASSWORD)

    await reset_password_with_token(
        db_session,
        first_token,
        new_password="NewStrong1!",
        confirm_password="NewStrong1!",
    )

    active_tokens = (
        await db_session.scalars(
            select(EmailToken).where(
                EmailToken.user_id == user.id,
                EmailToken.purpose == RESET_PASSWORD,
                EmailToken.consumed_at.is_(None),
            )
        )
    ).all()
    assert verify_password("NewStrong1!", user.password_hash)
    assert active_tokens == []
    with pytest.raises(EmailTokenError):
        await reset_password_with_token(
            db_session,
            first_token,
            new_password="OtherStrong1!",
            confirm_password="OtherStrong1!",
        )


async def test_reset_password_rejects_expired_token(
    db_session, make_user, disable_email_token_rate_limit
):
    issued_at = datetime(2026, 5, 17, tzinfo=UTC)
    user = await make_user(email="verified@example.com")
    user.email_verified = True
    db_session.add(user)
    await db_session.commit()
    _, raw_token = await issue_email_token(
        db_session,
        user,
        purpose=RESET_PASSWORD,
        now=issued_at,
    )

    with pytest.raises(EmailTokenError):
        await reset_password_with_token(
            db_session,
            raw_token,
            new_password="NewStrong1!",
            confirm_password="NewStrong1!",
            now=issued_at + timedelta(hours=1),
        )


async def test_reset_password_rejects_weak_mismatched_or_unverified_user(
    db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(
        email="unverified-reset@example.com",
        password_hash=hash_password("OldStrong1!"),
    )
    _, raw_token = await issue_email_token(
        db_session, user, purpose=RESET_PASSWORD
    )

    with pytest.raises(EmailTokenError, match="too weak"):
        await reset_password_with_token(
            db_session,
            raw_token,
            new_password="weak",
            confirm_password="weak",
        )
    with pytest.raises(EmailTokenError, match="do not match"):
        await reset_password_with_token(
            db_session,
            raw_token,
            new_password="NewStrong1!",
            confirm_password="OtherStrong1!",
        )
    with pytest.raises(EmailTokenError, match="Invalid or expired"):
        await reset_password_with_token(
            db_session,
            raw_token,
            new_password="NewStrong1!",
            confirm_password="NewStrong1!",
        )


async def test_invalidate_password_reset_tokens_uses_current_time(
    db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(email="invalidate-reset@example.com")
    user.email_verified = True
    db_session.add(user)
    await db_session.commit()
    await issue_email_token(db_session, user, purpose=RESET_PASSWORD)

    await invalidate_password_reset_tokens(db_session, user)

    active_token = await db_session.scalar(
        select(EmailToken).where(
            EmailToken.user_id == user.id,
            EmailToken.consumed_at.is_(None),
        )
    )
    assert active_token is None


async def test_register_post_creates_unverified_email_token(
    app_client, db_session
):
    response = app_client.post(
        "/register",
        data={
            "login": "emailtoken1",
            "email": "emailtoken1@example.com",
            "nickname": "Email_1",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "redirect_to": "/profile",
            "terms_accepted": "true",
        },
        follow_redirects=False,
    )
    user = await db_session.scalar(
        select(User).where(User.login == "emailtoken1")
    )
    token_count = await db_session.scalar(
        select(EmailToken).where(
            EmailToken.user_id == user.id,
            EmailToken.purpose == VERIFY_EMAIL,
        )
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert user.email_verified is False
    assert token_count is not None


async def test_forgot_password_route_keeps_generic_response(
    app_client, db_session, make_user, monkeypatch
):
    async def send_password_reset(user, email, reset_url):
        return None

    monkeypatch.setattr(
        "satoidc.services.email_tokens.send_password_reset",
        send_password_reset,
    )
    user = await make_user(email="verified@example.com")
    user.email_verified = True
    db_session.add(user)
    await db_session.commit()

    known = app_client.post(
        "/forgot-password",
        data={"email": "verified@example.com"},
        follow_redirects=False,
    )
    unknown = app_client.post(
        "/forgot-password",
        data={"email": "unknown@example.com"},
        follow_redirects=False,
    )

    assert known.status_code == HTTPStatus.SEE_OTHER
    assert unknown.status_code == HTTPStatus.SEE_OTHER
    assert known.headers["location"] == unknown.headers["location"]


async def test_forgot_password_route_keeps_generic_response_on_delivery_error(
    app_client, db_session, make_user, monkeypatch
):
    async def fail_send_password_reset(user, email, reset_url):
        raise EmailDeliveryError("SMTP delivery failed")

    monkeypatch.setattr(
        "satoidc.services.email_tokens.send_password_reset",
        fail_send_password_reset,
    )
    user = await make_user(email="verified@example.com")
    user.email_verified = True
    db_session.add(user)
    await db_session.commit()

    response = app_client.post(
        "/forgot-password",
        data={"email": "verified@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/forgot-password?sent=1"


async def test_verify_email_route_redirects_by_token_state(
    app_client, db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(email="verify-route@example.com")
    _, raw_token = await issue_email_token(
        db_session, user, purpose=VERIFY_EMAIL
    )

    success = app_client.get(
        f"/verify-email?token={raw_token}",
        follow_redirects=False,
    )
    failure = app_client.get(
        "/verify-email?token=invalid",
        follow_redirects=False,
    )

    assert success.status_code == HTTPStatus.SEE_OTHER
    assert success.headers["location"] == "/profile"
    assert failure.status_code == HTTPStatus.SEE_OTHER
    assert failure.headers["location"] == "/login?err=email_verification"


async def test_reset_password_route_redirects_by_token_state(
    app_client, db_session, make_user, disable_email_token_rate_limit
):
    user = await make_user(
        email="reset-route@example.com",
        password_hash=hash_password("OldStrong1!"),
    )
    user.email_verified = True
    db_session.add(user)
    await db_session.commit()
    _, raw_token = await issue_email_token(
        db_session, user, purpose=RESET_PASSWORD
    )

    success = app_client.post(
        "/reset-password",
        data={
            "token": raw_token,
            "password": "NewStrong1!",
            "confirm_password": "NewStrong1!",
        },
        follow_redirects=False,
    )
    failure = app_client.post(
        "/reset-password",
        data={
            "token": raw_token,
            "password": "OtherStrong1!",
            "confirm_password": "OtherStrong1!",
        },
        follow_redirects=False,
    )

    assert success.status_code == HTTPStatus.SEE_OTHER
    assert success.headers["location"] == "/login?reset=1"
    assert failure.status_code == HTTPStatus.SEE_OTHER
    assert failure.headers["location"] == "/reset-password?err=invalid"
