from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from satoidc.models.database import get_session
from sqlalchemy import select


async def exists_root_user() -> bool:
    async for session in get_session():
        result = await session.scalar(
            select(Permission).where(
                Permission.permission_type.is_(PermissionsEnum.ROOT)
            )
        )
        return result is not None
