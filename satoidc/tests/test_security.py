from satoidc.auth.security import (
    hash_password,
    is_authorized,
    verify_password,
)
from satoidc.enums import PermissionsEnum


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
