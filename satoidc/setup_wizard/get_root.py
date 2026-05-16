from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import verify_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission, User
from satoidc.models.database import get_session


async def exists_root_user() -> bool:
    async for session in get_session():
        result = await session.scalar(
            select(Permission).where(
                Permission.permission_type == PermissionsEnum.ROOT
            )
        )
        return result is not None

    return False


async def authenticate_root_user(
    session: AsyncSession,
    identifier: str | None,
    password: str | None,
) -> User | None:
    normalized_identifier = (identifier or "").strip().lower()
    if not normalized_identifier or not password:
        return None

    user = await session.scalar(
        select(User)
        .join(Permission, Permission.user_id == User.id)
        .where(
            User.is_active.is_(True),
            or_(
                User.email == normalized_identifier,
                User.login == normalized_identifier,
            ),
            User.password_hash.is_not(None),
            Permission.permission_type == PermissionsEnum.ROOT,
            Permission.disabled.is_(False),
            or_(
                Permission.expiration_date > func.now(),
                Permission.expiration_date.is_(None),
            ),
        )
    )
    if not user or not user.password_hash:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user


async def has_active_root_permission(
    session: AsyncSession,
    user_id,
) -> bool:
    root_permission = await session.scalar(
        select(Permission).where(
            Permission.user_id == user_id,
            Permission.permission_type == PermissionsEnum.ROOT,
            Permission.disabled.is_(False),
            or_(
                Permission.expiration_date > func.now(),
                Permission.expiration_date.is_(None),
            ),
        )
    )
    return root_permission is not None
