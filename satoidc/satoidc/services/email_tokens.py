import hashlib
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import hash_password
from satoidc.models import EmailToken, User
from satoidc.services.email_delivery import (
    send_email_verification,
    send_password_reset,
)
from satoidc.settings import ENV
from satoidc.validators import is_valid_email, is_valid_password

VERIFY_EMAIL = "verify_email"
RESET_PASSWORD = "reset_password"
RECOVERY_REQUEST_MESSAGE = (
    "If an account can be recovered for that email, a message has been sent."
)


class EmailTokenError(ValueError):
    """Raised when an email-token action cannot be completed."""


class EmailTokenRateLimited(EmailTokenError):
    """Raised when token issuance is attempted too frequently."""


def _now() -> datetime:
    return datetime.now(UTC)


def hash_email_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _hash_optional(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def public_base_url(request_base_url: str | None = None) -> str:
    base_url = (
        ENV.EMAIL_PUBLIC_BASE_URL or request_base_url or ENV.OAUTH2_JWT_ISS
    )
    return base_url.rstrip("/")


def build_email_url(
    path: str, token: str, *, request_base_url: str | None = None
) -> str:
    query = urlencode({"token": token})
    return f"{public_base_url(request_base_url)}{path}?{query}"


async def _consume_active_tokens(
    session: AsyncSession,
    *,
    user_id,
    purpose: str,
    now: datetime,
) -> None:
    active_tokens = (
        await session.scalars(
            select(EmailToken).where(
                EmailToken.user_id == user_id,
                EmailToken.purpose == purpose,
                EmailToken.consumed_at.is_(None),
            )
        )
    ).all()
    for token in active_tokens:
        token.consumed_at = now
        session.add(token)


async def issue_email_token(  # noqa: PLR0913
    session: AsyncSession,
    user: User,
    *,
    purpose: str,
    request_ip: str | None = None,
    user_agent: str | None = None,
    now: datetime | None = None,
) -> tuple[EmailToken, str]:
    if not user.email:
        raise EmailTokenError("No email address is linked to this account.")
    issued_at = now or _now()
    recent_cutoff = issued_at - timedelta(
        seconds=ENV.EMAIL_TOKEN_MIN_REQUEST_INTERVAL_SECONDS
    )
    recent_token = await session.scalar(
        select(EmailToken).where(
            EmailToken.user_id == user.id,
            EmailToken.email == user.email,
            EmailToken.purpose == purpose,
            EmailToken.consumed_at.is_(None),
            EmailToken.created_at >= recent_cutoff,
        )
    )
    if recent_token:
        raise EmailTokenRateLimited(
            "Please wait before requesting another email."
        )

    raw_token = token_urlsafe(48)
    ttl_seconds = (
        ENV.EMAIL_VERIFICATION_TOKEN_TTL_SECONDS
        if purpose == VERIFY_EMAIL
        else ENV.EMAIL_RESET_TOKEN_TTL_SECONDS
    )
    email_token = EmailToken(
        user_id=user.id,
        email=user.email,
        purpose=purpose,
        token_hash=hash_email_token(raw_token),
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
        request_ip_hash=_hash_optional(request_ip),
        user_agent_hash=_hash_optional(user_agent),
    )
    session.add(email_token)
    await session.commit()
    await session.refresh(email_token)
    return email_token, raw_token


async def request_email_verification(
    session: AsyncSession,
    user: User,
    *,
    request_base_url: str | None = None,
    request_ip: str | None = None,
    user_agent: str | None = None,
) -> EmailToken:
    if not user.email:
        raise EmailTokenError("No email address is linked to this account.")
    if user.email_verified:
        raise EmailTokenError("Email is already verified.")
    email_token, raw_token = await issue_email_token(
        session,
        user,
        purpose=VERIFY_EMAIL,
        request_ip=request_ip,
        user_agent=user_agent,
    )
    verification_url = build_email_url(
        "/verify-email", raw_token, request_base_url=request_base_url
    )
    await send_email_verification(user, user.email, verification_url)
    return email_token


async def verify_email_token(
    session: AsyncSession,
    raw_token: str | None,
    *,
    now: datetime | None = None,
) -> User:
    if not raw_token:
        raise EmailTokenError("Invalid or expired verification link.")
    checked_at = now or _now()
    email_token = await session.scalar(
        select(EmailToken).where(
            EmailToken.token_hash == hash_email_token(raw_token),
            EmailToken.purpose == VERIFY_EMAIL,
            EmailToken.consumed_at.is_(None),
            EmailToken.expires_at >= checked_at,
        )
    )
    if not email_token:
        raise EmailTokenError("Invalid or expired verification link.")
    user = await session.get(User, email_token.user_id)
    if not user or user.email != email_token.email:
        raise EmailTokenError("Invalid or expired verification link.")

    user.email_verified = True
    user.email_verified_at = checked_at
    await _consume_active_tokens(
        session, user_id=user.id, purpose=VERIFY_EMAIL, now=checked_at
    )
    session.add(user)
    await session.commit()
    return user


async def request_password_reset(
    session: AsyncSession,
    email: str | None,
    *,
    request_base_url: str | None = None,
    request_ip: str | None = None,
    user_agent: str | None = None,
) -> str:
    normalized_email = (email or "").strip().lower()
    if not is_valid_email(normalized_email):
        return RECOVERY_REQUEST_MESSAGE
    user = await session.scalar(
        select(User).where(User.email == normalized_email)
    )
    if not user or not user.email_verified:
        return RECOVERY_REQUEST_MESSAGE
    try:
        _, raw_token = await issue_email_token(
            session,
            user,
            purpose=RESET_PASSWORD,
            request_ip=request_ip,
            user_agent=user_agent,
        )
    except EmailTokenRateLimited:
        return RECOVERY_REQUEST_MESSAGE
    reset_url = build_email_url(
        "/reset-password", raw_token, request_base_url=request_base_url
    )
    await send_password_reset(user, normalized_email, reset_url)
    return RECOVERY_REQUEST_MESSAGE


async def reset_password_with_token(
    session: AsyncSession,
    raw_token: str | None,
    *,
    new_password: str | None,
    confirm_password: str | None,
    now: datetime | None = None,
) -> User:
    if not is_valid_password(new_password or ""):
        raise EmailTokenError("New password is too weak.")
    if new_password != confirm_password:
        raise EmailTokenError("Passwords do not match.")
    checked_at = now or _now()
    email_token = await session.scalar(
        select(EmailToken).where(
            EmailToken.token_hash == hash_email_token(raw_token or ""),
            EmailToken.purpose == RESET_PASSWORD,
            EmailToken.consumed_at.is_(None),
            EmailToken.expires_at >= checked_at,
        )
    )
    if not email_token:
        raise EmailTokenError("Invalid or expired reset link.")
    user = await session.get(User, email_token.user_id)
    if not user or user.email != email_token.email or not user.email_verified:
        raise EmailTokenError("Invalid or expired reset link.")

    user.password_hash = hash_password(new_password or "")
    await _consume_active_tokens(
        session, user_id=user.id, purpose=RESET_PASSWORD, now=checked_at
    )
    session.add(user)
    await session.commit()
    return user


async def invalidate_password_reset_tokens(
    session: AsyncSession, user: User, *, now: datetime | None = None
) -> None:
    await _consume_active_tokens(
        session,
        user_id=user.id,
        purpose=RESET_PASSWORD,
        now=now or _now(),
    )
