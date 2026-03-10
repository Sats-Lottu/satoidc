from functools import wraps
from typing import Literal
from uuid import UUID

from nicegui import ui
from pwdlib import PasswordHash
from sqlalchemy import func, or_, select
from starlette.responses import RedirectResponse

from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from satoidc.models.database import get_session

pwd_context = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


PermissionMode = Literal["all", "any"]


def is_authorized(
    user_permissions: set[str],
    required_permissions: set[str],
    *,
    mode: PermissionMode = "all",
) -> bool:
    if PermissionsEnum.ROOT in user_permissions:
        return True

    if mode == "all":
        return required_permissions.issubset(user_permissions)

    if mode == "any":
        return not required_permissions.isdisjoint(user_permissions)

    raise ValueError(f"Invalid permission mode: {mode}")


def page_security(
    *,
    permissions: list[str] | None = None,
    mode: PermissionMode = "any",
):
    required_permissions = set(permissions or [PermissionsEnum.ROOT])

    def decorator(page_func):
        @wraps(page_func)
        async def wrapper(*args, **kwargs):
            request = ui.context.client.request
            user_id = request.session.get("user_id")
            if not user_id:
                return RedirectResponse("/login")
            async for session in get_session():
                result = await session.scalars(
                    select(Permission.permission_type).where(
                        Permission.user_id == UUID(user_id),
                        Permission.disabled.is_(False),
                        or_(
                            Permission.expiration_date > func.now(),
                            Permission.expiration_date.is_(None),
                        ),
                    )
                )
                user_permissions = set(result.all())
            print(f"User {user_id} permissions: {user_permissions}")
            if not is_authorized(
                user_permissions,
                required_permissions,
                mode=mode,
            ):
                return RedirectResponse("/forbidden")

            await page_func(*args, **kwargs)

        return wrapper

    return decorator
