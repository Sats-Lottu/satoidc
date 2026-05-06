from satoidc.enums import PermissionsEnum
from satoidc.models import Permission
from setup_wizard.get_root import exists_root_user


async def test_setup_wizard_detects_missing_root_user(db_session):
    assert await exists_root_user() is False


async def test_setup_wizard_detects_existing_root_user(
    db_session, make_user
):
    user = await make_user()
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=None,
            reason="test root user",
        )
    )
    await db_session.commit()

    assert await exists_root_user() is True
