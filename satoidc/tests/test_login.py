from http import HTTPStatus
from types import SimpleNamespace

import satoidc.routes.login as login_module
from satoidc.auth.security import hash_password
from satoidc.routes.login import (
    encode_query_value,
    lnurl_auth_temp_storage,
    lnurl_redirect,
    login_post,
    logout,
)
from satoidc.schemas.login import LoginSchema


async def test_login_post_rejects_missing_or_mismatched_nonce(db_session):
    request = SimpleNamespace(session={"login_nonce": "expected"})
    form = LoginSchema(
        identifier="satoshi1",
        password="StrongPass1!",
        redirect_to="/profile",
        login_nonce="wrong",
    )

    response = await login_post(db_session, request, form)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/login?err=bad_flow"
    assert "login_nonce" not in request.session


async def test_login_post_rejects_invalid_credentials(db_session, make_user):
    await make_user(password_hash=hash_password("StrongPass1!"))
    request = SimpleNamespace(session={"login_nonce": "nonce"})
    form = LoginSchema(
        identifier="satoshi1",
        password="WrongPass1!",
        redirect_to="/profile?tab=wallet",
        login_nonce="nonce",
    )

    response = await login_post(db_session, request, form)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/login?err=invalid&redirect_to=%2Fprofile%3Ftab%3Dwallet"
    )


async def test_login_post_accepts_email_or_login(db_session, make_user):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    request = SimpleNamespace(session={"login_nonce": "nonce"})
    form = LoginSchema(
        identifier=user.email,
        password="StrongPass1!",
        redirect_to="/profile",
        login_nonce="nonce",
    )

    response = await login_post(db_session, request, form)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/profile"
    assert request.session["user_id"] == user.id.hex


async def test_login_post_sanitizes_external_redirect(db_session, make_user):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    request = SimpleNamespace(session={"login_nonce": "nonce"})
    form = LoginSchema(
        identifier=user.email,
        password="StrongPass1!",
        redirect_to="https://evil.example/callback",
        login_nonce="nonce",
    )

    response = await login_post(db_session, request, form)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/"
    assert request.session["user_id"] == user.id.hex


async def test_login_post_sanitizes_host_relative_redirect(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    request = SimpleNamespace(session={"login_nonce": "nonce"})
    form = LoginSchema(
        identifier=user.login,
        password="StrongPass1!",
        redirect_to="//evil.example/callback",
        login_nonce="nonce",
    )

    response = await login_post(db_session, request, form)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/"


async def test_login_post_sanitizes_empty_redirect(db_session, make_user):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    request = SimpleNamespace(session={"login_nonce": "nonce"})
    form = LoginSchema(
        identifier=user.login,
        password="StrongPass1!",
        redirect_to="",
        login_nonce="nonce",
    )

    response = await login_post(db_session, request, form)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/"


async def test_lnurl_redirect_moves_transient_user_to_session(monkeypatch):
    monkeypatch.setattr(
        login_module.ui,
        "label",
        lambda *args, **kwargs: SimpleNamespace(
            classes=lambda *args, **kwargs: None
        ),
    )
    monkeypatch.setattr(
        login_module.ui.navigate, "to", lambda *args, **kwargs: None
    )
    request = SimpleNamespace(session={"login_nonce": "nonce"})
    lnurl_auth_temp_storage["nonce"] = "user-1"

    await lnurl_redirect(request, "/profile")

    assert request.session["user_id"] == "user-1"
    assert "nonce" not in lnurl_auth_temp_storage


async def test_lnurl_redirect_sanitizes_redirect_to(monkeypatch):
    navigations = []
    monkeypatch.setattr(
        login_module.ui,
        "label",
        lambda *args, **kwargs: SimpleNamespace(
            classes=lambda *args, **kwargs: None
        ),
    )
    monkeypatch.setattr(login_module.ui.navigate, "to", navigations.append)
    request = SimpleNamespace(session={"login_nonce": "nonce"})
    lnurl_auth_temp_storage["nonce"] = "user-1"

    await lnurl_redirect(request, "https://evil.example")

    assert navigations == ["/"]


def test_logout_clears_session_and_redirects_home():
    request = SimpleNamespace(session={"user_id": "user-1"})

    response = logout(request)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == "/"
    assert request.session == {}


def test_encode_query_value_handles_empty_values():
    assert not encode_query_value("")
    assert encode_query_value("/profile?tab=wallet") == (
        "%2Fprofile%3Ftab%3Dwallet"
    )


def test_hidden_value_escapes_single_quotes_without_url_encoding():
    assert login_module._hidden_value("/authorize?prompt='login'") == (  # noqa: PLC2701
        "/authorize?prompt=&#x27;login&#x27;"
    )
