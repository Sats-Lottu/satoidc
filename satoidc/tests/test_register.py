from http import HTTPStatus

from sqlalchemy import select

from satoidc.auth.security import verify_password
from satoidc.models import User
from satoidc.routes.register import register_redirect
from satoidc.services.email_delivery import EmailDeliveryError


def test_register_redirect_sanitizes_external_redirect_target():
    response = register_redirect("invalid", "https://evil.example/callback")

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/register?err=invalid&redirect_to=%2F"
    )


async def test_register_post_creates_user_and_logs_in(app_client, db_session):
    response = app_client.post(
        "/register",
        data={
            "login": "satoshi2",
            "email": "satoshi2@example.com",
            "nickname": "Satoshi_2",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "redirect_to": "/profile",
            "terms_accepted": "true",
        },
        follow_redirects=False,
    )

    user = await db_session.scalar(
        select(User).where(User.login == "satoshi2")
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/profile"
    assert user is not None
    assert user.email == "satoshi2@example.com"
    assert user.password_hash is not None
    assert verify_password("StrongPass1!", user.password_hash)
    assert app_client.cookies.get("client_session") is not None


async def test_register_post_rejects_duplicate_login(
    app_client, db_session, make_user
):
    await make_user(login="satoshi3", email="satoshi3@example.com")

    response = app_client.post(
        "/register",
        data={
            "login": "satoshi3",
            "email": "other@example.com",
            "nickname": "Satoshi_3",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "redirect_to": "/profile",
            "terms_accepted": "true",
        },
        follow_redirects=False,
    )

    users = (
        await db_session.scalars(
            select(User).where(User.login == "satoshi3")
        )
    ).all()

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/register?err=duplicate&redirect_to=%2Fprofile"
    )
    assert len(users) == 1


async def test_register_post_requires_terms(app_client, db_session):
    response = app_client.post(
        "/register",
        data={
            "login": "satoshi4",
            "email": "satoshi4@example.com",
            "nickname": "Satoshi_4",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "redirect_to": "/profile",
        },
        follow_redirects=False,
    )
    user = await db_session.scalar(
        select(User).where(User.login == "satoshi4")
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/register?err=terms&redirect_to=%2Fprofile"
    )
    assert user is None


async def test_register_post_rejects_invalid_data(app_client, db_session):
    response = app_client.post(
        "/register",
        data={
            "login": "bad",
            "email": "not-an-email",
            "nickname": "-bad-",
            "password": "weak",
            "confirm_password": "weak",
            "redirect_to": "https://evil.example",
            "terms_accepted": "true",
        },
        follow_redirects=False,
    )
    users = (await db_session.scalars(select(User))).all()

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/register?err=invalid&redirect_to=%2F"
    )
    assert users == []


async def test_register_post_rejects_password_mismatch(
    app_client, db_session
):
    response = app_client.post(
        "/register",
        data={
            "login": "satoshi5",
            "email": "satoshi5@example.com",
            "nickname": "Satoshi_5",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass2!",
            "redirect_to": "/profile",
            "terms_accepted": "true",
        },
        follow_redirects=False,
    )
    user = await db_session.scalar(
        select(User).where(User.login == "satoshi5")
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/register?err=password_mismatch&redirect_to=%2Fprofile"
    )
    assert user is None


async def test_register_post_redirects_on_email_delivery_error(
    app_client, db_session, monkeypatch
):
    async def fail_email_verification(*args, **kwargs):
        raise EmailDeliveryError("SMTP delivery failed")

    monkeypatch.setattr(
        "satoidc.routes.register.request_email_verification",
        fail_email_verification,
    )

    response = app_client.post(
        "/register",
        data={
            "login": "satoshiemailerror",
            "email": "satoshi-email-error@example.com",
            "nickname": "SatoshiEmailError",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "redirect_to": "/profile",
            "terms_accepted": "true",
        },
        follow_redirects=False,
    )
    user = await db_session.scalar(
        select(User).where(User.login == "satoshiemailerror")
    )

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/register?err=email_delivery&redirect_to=%2Fprofile"
    )
    assert user is not None
