from uuid import UUID

from sqlalchemy import func, inspect, or_, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import verify_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission, User
from satoidc.models.database import get_session


def is_missing_schema_error(exc: OperationalError) -> bool:
    message = str(exc.orig).lower()
    return "no such table" in message or "does not exist" in message


def parse_root_user_id(value) -> UUID | None:
    if isinstance(value, UUID):
        return value
    if not value:
        return None
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


async def database_schema_ready() -> bool:
    async for session in get_session():
        table_names = await session.run_sync(
            lambda sync_session: inspect(
                sync_session.get_bind()
            ).get_table_names()
        )
        return {"users", "permissions"}.issubset(set(table_names))

    return False


async def exists_root_user() -> bool:
    async for session in get_session():
        try:
            result = await session.scalar(
                select(Permission).where(
                    Permission.permission_type == PermissionsEnum.ROOT
                )
            )
        except OperationalError as exc:
            if is_missing_schema_error(exc):
                return False
            raise
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

    try:
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
    except OperationalError as exc:
        if is_missing_schema_error(exc):
            return None
        raise
    if not user or not user.password_hash:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user


async def has_active_root_permission(
    session: AsyncSession,
    user_id,
) -> bool:
    parsed_user_id = parse_root_user_id(user_id)
    if parsed_user_id is None:
        return False

    try:
        root_permission = await session.scalar(
            select(Permission).where(
                Permission.user_id == parsed_user_id,
                Permission.permission_type == PermissionsEnum.ROOT,
                Permission.disabled.is_(False),
                or_(
                    Permission.expiration_date > func.now(),
                    Permission.expiration_date.is_(None),
                ),
            )
        )
    except OperationalError as exc:
        if is_missing_schema_error(exc):
            return False
        raise
    return root_permission is not None
