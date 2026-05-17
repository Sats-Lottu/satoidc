from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import hash_password, verify_password
from satoidc.models import LnurlAuthChallenge, User
from satoidc.services.email_tokens import invalidate_password_reset_tokens
from satoidc.validators import (
    is_valid_email,
    is_valid_nickname,
    is_valid_password,
)


class ProfileServiceError(ValueError):
    """Raised when a profile action cannot be completed."""


async def update_profile_nickname(
    session: AsyncSession, user: User, nickname: str | None
) -> User:
    value = (nickname or "").strip()
    if not is_valid_nickname(value):
        raise ProfileServiceError("Invalid nickname format.")
    user.nickname = value or "Satoshi"
    session.add(user)
    await session.commit()
    return user


async def update_profile_email(
    session: AsyncSession, user: User, email: str | None
) -> User:
    value = (email or "").strip().lower()
    if not is_valid_email(value):
        raise ProfileServiceError("Invalid email address.")
    existing_user = await session.scalar(
        select(User).where(User.email == value, User.id != user.id)
    )
    if existing_user:
        raise ProfileServiceError("Email is already in use.")
    user.email = value
    user.email_verified = False
    user.email_verified_at = None
    session.add(user)
    await invalidate_password_reset_tokens(session, user)
    await session.commit()
    return user


async def update_profile_password(
    session: AsyncSession,
    user: User,
    *,
    current_password: str | None,
    new_password: str | None,
    confirm_password: str | None,
) -> User:
    if user.password_hash and not verify_password(
        current_password or "", user.password_hash
    ):
        raise ProfileServiceError("Current password is incorrect.")
    if not is_valid_password(new_password or ""):
        raise ProfileServiceError("New password is too weak.")
    if new_password != confirm_password:
        raise ProfileServiceError("Passwords do not match.")
    user.password_hash = hash_password(new_password or "")
    session.add(user)
    await session.commit()
    return user


async def unlink_profile_wallet(session: AsyncSession, user: User) -> User:
    if not user.password_hash:
        raise ProfileServiceError(
            "Set a password before unlinking this wallet."
        )
    user.lnurl_pubkey = None
    session.add(user)
    await session.commit()
    return user


async def create_wallet_link_challenge(
    session: AsyncSession, user: User
) -> LnurlAuthChallenge:
    challenge = LnurlAuthChallenge(action="link", user_id=user.id)
    session.add(challenge)
    await session.commit()
    await session.refresh(challenge)
    return challenge
