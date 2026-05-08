from collections.abc import Iterable
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
    user_permissions: Iterable[str],
    required_permissions: Iterable[str],
    *,
    mode: PermissionMode = "all",
) -> bool:
    user_permission_values = {
        str(permission) for permission in user_permissions
    }
    required_permission_values = {
        str(permission) for permission in required_permissions
    }

    if str(PermissionsEnum.ROOT) in user_permission_values:
        return True

    if mode == "all":
        return required_permission_values.issubset(user_permission_values)

    if mode == "any":
        return not required_permission_values.isdisjoint(
            user_permission_values
        )

    raise ValueError(f"Invalid permission mode: {mode}")


async def get_active_user_permissions(
    user_id: UUID,
    *,
    session_factory=get_session,
) -> set[str]:
    async for session in session_factory():
        result = await session.scalars(
            select(Permission.permission_type).where(
                Permission.user_id == user_id,
                Permission.disabled.is_(False),
                or_(
                    Permission.expiration_date > func.now(),
                    Permission.expiration_date.is_(None),
                ),
            )
        )
        return {str(permission) for permission in result.all()}
    return set()


async def authorize_page_request(
    request,
    required_permissions: Iterable[str],
    *,
    mode: PermissionMode = "any",
    session_factory=get_session,
) -> RedirectResponse | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    try:
        user_uuid = UUID(user_id)
    except (TypeError, ValueError):
        return RedirectResponse("/login")

    user_permissions = await get_active_user_permissions(
        user_uuid, session_factory=session_factory
    )
    if not is_authorized(
        user_permissions,
        required_permissions,
        mode=mode,
    ):
        return RedirectResponse("/forbidden")

    return None


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
            redirect = await authorize_page_request(
                request,
                required_permissions,
                mode=mode,
            )
            if redirect:
                return redirect

            return await page_func(*args, **kwargs)

        return wrapper

    return decorator
