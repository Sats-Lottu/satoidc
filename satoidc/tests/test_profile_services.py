import pytest
from sqlalchemy import select

from satoidc.auth.security import hash_password, verify_password
from satoidc.models import LnurlAuthChallenge, User
from satoidc.services.profile import (
    ProfileServiceError,
    create_wallet_link_challenge,
    unlink_profile_wallet,
    update_profile_email,
    update_profile_nickname,
    update_profile_password,
)


async def test_update_profile_nickname_normalizes_blank_value(
    db_session, make_user
):
    user = await make_user(nickname="Old")

    await update_profile_nickname(db_session, user, " ")

    stored = await db_session.get(User, user.id)
    assert stored.nickname == "Satoshi"


async def test_update_profile_nickname_rejects_invalid_value(
    db_session, make_user
):
    user = await make_user(nickname="Old")

    with pytest.raises(ProfileServiceError) as exc_info:
        await update_profile_nickname(db_session, user, ".invalid")

    assert str(exc_info.value) == "Invalid nickname format."
    assert user.nickname == "Old"


async def test_update_profile_email_persists_normalized_value(
    db_session, make_user
):
    user = await make_user(email="old@example.com")

    await update_profile_email(db_session, user, " New@Example.COM ")

    stored = await db_session.get(User, user.id)
    assert stored.email == "new@example.com"


async def test_update_profile_email_rejects_duplicate(
    db_session, make_user
):
    user = await make_user(login="satoshi1", email="first@example.com")
    await make_user(login="satoshi2", email="taken@example.com")

    with pytest.raises(ProfileServiceError) as exc_info:
        await update_profile_email(db_session, user, "TAKEN@example.com")

    assert str(exc_info.value) == "Email is already in use."
    assert user.email == "first@example.com"


async def test_update_profile_email_rejects_invalid_address(
    db_session, make_user
):
    user = await make_user(email="profile@example.com")

    with pytest.raises(ProfileServiceError) as exc_info:
        await update_profile_email(db_session, user, "not-an-email")

    assert str(exc_info.value) == "Invalid email address."


async def test_update_profile_password_requires_current_password(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))

    with pytest.raises(ProfileServiceError) as exc_info:
        await update_profile_password(
            db_session,
            user,
            current_password="WrongPass1!",
            new_password="NewStrong1!",
            confirm_password="NewStrong1!",
        )

    assert str(exc_info.value) == "Current password is incorrect."


async def test_update_profile_password_persists_hash(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))

    await update_profile_password(
        db_session,
        user,
        current_password="StrongPass1!",
        new_password="NewStrong1!",
        confirm_password="NewStrong1!",
    )

    assert verify_password("NewStrong1!", user.password_hash)


async def test_update_profile_password_allows_passwordless_account(
    db_session, make_user
):
    user = await make_user(password_hash=None)

    await update_profile_password(
        db_session,
        user,
        current_password=None,
        new_password="NewStrong1!",
        confirm_password="NewStrong1!",
    )

    assert verify_password("NewStrong1!", user.password_hash)


async def test_update_profile_password_rejects_weak_password(
    db_session, make_user
):
    user = await make_user(password_hash=None)

    with pytest.raises(ProfileServiceError) as exc_info:
        await update_profile_password(
            db_session,
            user,
            current_password=None,
            new_password="weak",
            confirm_password="weak",
        )

    assert str(exc_info.value) == "New password is too weak."


async def test_update_profile_password_rejects_mismatch(
    db_session, make_user
):
    user = await make_user(password_hash=None)

    with pytest.raises(ProfileServiceError) as exc_info:
        await update_profile_password(
            db_session,
            user,
            current_password=None,
            new_password="NewStrong1!",
            confirm_password="OtherStrong1!",
        )

    assert str(exc_info.value) == "Passwords do not match."


async def test_unlink_profile_wallet_requires_password(
    db_session, make_user
):
    user = await make_user(lnurl_pubkey="pubkey", password_hash=None)

    with pytest.raises(ProfileServiceError) as exc_info:
        await unlink_profile_wallet(db_session, user)

    assert str(exc_info.value) == (
        "Set a password before unlinking this wallet."
    )
    assert user.lnurl_pubkey == "pubkey"


async def test_unlink_profile_wallet_persists_without_removing_password(
    db_session, make_user
):
    password_hash = hash_password("StrongPass1!")
    user = await make_user(
        lnurl_pubkey="pubkey", password_hash=password_hash
    )

    await unlink_profile_wallet(db_session, user)

    assert user.lnurl_pubkey is None
    assert user.password_hash == password_hash


async def test_create_wallet_link_challenge_persists_link_action(
    db_session, make_user
):
    user = await make_user()

    challenge = await create_wallet_link_challenge(db_session, user)

    stored = await db_session.scalar(
        select(LnurlAuthChallenge).where(
            LnurlAuthChallenge.k1 == challenge.k1
        )
    )
    assert stored is not None
    assert stored.user_id == user.id
    assert stored.action == "link"
