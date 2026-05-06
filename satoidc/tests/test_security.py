from http import HTTPStatus

import pytest

from satoidc.auth.security import (
    hash_password,
    is_authorized,
    verify_password,
)
from satoidc.enums import PermissionsEnum
from satoidc.utils import safe_redirect


def test_password_hashing_uses_real_hasher():
    password_hash = hash_password("StrongPass1!")

    assert password_hash != "StrongPass1!"
    assert verify_password("StrongPass1!", password_hash)
    assert not verify_password("WrongPass1!", password_hash)


def test_root_permission_authorizes_everything():
    assert is_authorized(
        {PermissionsEnum.ROOT},
        {PermissionsEnum.ADMIN, PermissionsEnum.SUPPORT},
    )


def test_permission_modes_require_all_or_any():
    user_permissions = {PermissionsEnum.ADMIN}

    assert is_authorized(
        user_permissions,
        {PermissionsEnum.ADMIN, PermissionsEnum.SUPPORT},
        mode="any",
    )
    assert not is_authorized(
        user_permissions,
        {PermissionsEnum.ADMIN, PermissionsEnum.SUPPORT},
        mode="all",
    )


def test_invalid_permission_mode_is_rejected():
    with pytest.raises(ValueError, match="Invalid permission mode"):
        is_authorized(
            {PermissionsEnum.ADMIN},
            {PermissionsEnum.ADMIN},
            mode="invalid",
        )


def test_safe_redirect_accepts_only_relative_paths():
    assert safe_redirect("/profile") == "/profile"
    assert safe_redirect("/profile?tab=wallet") == "/profile?tab=wallet"
    assert safe_redirect(None) == "/"
    assert safe_redirect("") == "/"
    assert safe_redirect("profile") == "/"
    assert safe_redirect("https://evil.example/login") == "/"
    assert safe_redirect("//evil.example/login") == "/"


def test_auth_middleware_redirects_protected_route(app_client):
    response = app_client.get("/profile?tab=wallet", follow_redirects=False)

    assert response.status_code == HTTPStatus.SEE_OTHER
    assert response.headers["location"] == (
        "/login?redirect_to=%2Fprofile%3Ftab%3Dwallet"
    )


def test_auth_middleware_allows_public_oauth_route(app_client):
    response = app_client.get("/.well-known/jwks.json")

    assert response.status_code == HTTPStatus.OK
