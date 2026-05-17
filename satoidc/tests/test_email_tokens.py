from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import pytest
from sqlalchemy import select

import satoidc.services.email_tokens as email_tokens_module
from satoidc.auth.security import hash_password, verify_password
from satoidc.models import EmailToken, User
from satoidc.services.email_tokens import (
    RESET_PASSWORD,
    VERIFY_EMAIL,
    EmailTokenError,
    hash_email_token,
    issue_email_token,
    request_password_reset,
    reset_password_with_token,
    verify_email_token,
)


async def test_issue_email_token_stores_only_hash(
    db_session, make_user, monkeypatch
):
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        0,
    )
    user = await make_user(email="satoshi@example.com")

    email_token, raw_token = await issue_email_token(
        db_session, user, purpose=VERIFY_EMAIL
    )

    assert raw_token
    assert email_token.token_hash == hash_email_token(raw_token)
    assert raw_token not in email_token.token_hash


async def test_verify_email_token_marks_email_verified_once(
    db_session, make_user, monkeypatch
):
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        0,
    )
    user = await make_user(email="satoshi@example.com")
    _, raw_token = await issue_email_token(
        db_session, user, purpose=VERIFY_EMAIL
    )

    verified_user = await verify_email_token(db_session, raw_token)

    assert verified_user.email_verified is True
    assert verified_user.email_verified_at is not None
    with pytest.raises(EmailTokenError):
        await verify_email_token(db_session, raw_token)


async def test_verify_email_token_rejects_old_email(
    db_session, make_user, monkeypatch
):
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        0,
    )
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


async def test_reset_password_with_token_consumes_all_active_reset_tokens(
    db_session, make_user, monkeypatch
):
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        0,
    )
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
    db_session, make_user, monkeypatch
):
    monkeypatch.setattr(
        email_tokens_module.ENV,
        "EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS",
        0,
    )
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
