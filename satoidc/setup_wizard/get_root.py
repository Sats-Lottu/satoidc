from sqlalchemy import select

from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from satoidc.models.database import get_session


async def exists_root_user() -> bool:
    async for session in get_session():
        result = await session.scalar(
            select(Permission).where(
                Permission.permission_type == PermissionsEnum.ROOT
            )
        )
        return result is not None
