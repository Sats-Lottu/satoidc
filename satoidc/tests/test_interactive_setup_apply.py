from sqlalchemy import select

from satoidc.auth.security import verify_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission, SetupState, User
from satoidc.services.setup_lock import acquire_setup_lock
from setup_wizard.apply import (
    InteractiveSetupAdminPayload,
    InteractiveSetupApplyStatus,
    apply_interactive_setup_admin,
)

VALID_PAYLOAD = InteractiveSetupAdminPayload(
    username="rootadm",
    email="root@example.com",
    password="StrongPass1!",
    password_confirmation="StrongPass1!",
)


async def test_interactive_setup_apply_creates_root_and_completes_state(
    db_session, assert_no_sensitive_log_values
):
    result = await apply_interactive_setup_admin(
        db_session, VALID_PAYLOAD, actor="wizard-session"
    )

    user = await db_session.scalar(
        select(User).where(User.login == "rootadm")
    )
    permission = await db_session.scalar(
        select(Permission).where(
            Permission.user_id == user.id,
            Permission.permission_type == PermissionsEnum.ROOT,
        )
    )
    setup_state = await db_session.get(SetupState, 1)

    assert result.status == InteractiveSetupApplyStatus.APPLIED
    assert result.applied is True
    assert result.user_id == str(user.id)
    assert result.setup_state == "completed"
    assert user.email == "root@example.com"
    assert user.email_verified is True
    assert verify_password("StrongPass1!", user.password_hash)
    assert user.password_hash != "StrongPass1!"
    assert permission is not None
    assert permission.granted_by is None
    assert setup_state.state == "completed"
    assert setup_state.completed_by == "wizard-session"
    assert setup_state.config_hash.startswith("sha256:")
    assert setup_state.last_error is None
    assert_no_sensitive_log_values("StrongPass1!")
    assert "StrongPass1!" not in repr(result)


async def test_interactive_setup_apply_returns_validation_errors(db_session):
    result = await apply_interactive_setup_admin(
        db_session,
        InteractiveSetupAdminPayload(
            username="Root",
            email="not-email",
            password="weak",
            password_confirmation="different",
        ),
    )
    user = await db_session.scalar(select(User))
    setup_state = await db_session.get(SetupState, 1)

    assert result.status == InteractiveSetupApplyStatus.VALIDATION_ERROR
    assert set(result.errors) == {
        "username",
        "email",
        "password",
        "password_confirmation",
    }
    assert "weak" not in repr(result)
    assert user is None
    assert setup_state is None


async def test_interactive_setup_apply_blocks_existing_admin(
    db_session, make_user
):
    admin = await make_user(login="admin1", email="admin@example.com")
    db_session.add(
        Permission(
            user_id=admin.id,
            granted_by=None,
            permission_type=PermissionsEnum.ADMIN,
            expiration_date=None,
            reason="existing admin",
        )
    )
    await db_session.commit()

    result = await apply_interactive_setup_admin(db_session, VALID_PAYLOAD)
    users = (await db_session.scalars(select(User))).all()
    setup_state = await db_session.get(SetupState, 1)

    assert result.status == InteractiveSetupApplyStatus.ADMIN_EXISTS
    assert result.errors == {"admin": "A root/admin user already exists."}
    assert len(users) == 1
    assert setup_state is None


async def test_interactive_setup_apply_reports_lock_unavailable(db_session):
    await acquire_setup_lock(db_session, actor="another-setup")

    result = await apply_interactive_setup_admin(db_session, VALID_PAYLOAD)
    user = await db_session.scalar(select(User))
    setup_state = await db_session.get(SetupState, 1)

    assert result.status == InteractiveSetupApplyStatus.LOCK_UNAVAILABLE
    assert result.setup_state == "applying"
    assert result.diagnostics.current_state == "applying"
    assert "setup_lock" in result.errors
    assert user is None
    assert setup_state.state == "applying"


async def test_interactive_setup_apply_marks_failed_without_password_leak(
    db_session, monkeypatch, assert_no_sensitive_log_values
):
    def broken_hash_password(password: str) -> str:
        raise RuntimeError(f"hash failed for {password}")

    monkeypatch.setattr(
        "setup_wizard.apply.security.hash_password", broken_hash_password
    )

    result = await apply_interactive_setup_admin(db_session, VALID_PAYLOAD)
    user = await db_session.scalar(select(User))
    setup_state = await db_session.get(SetupState, 1)

    assert result.status == InteractiveSetupApplyStatus.FAILED
    assert result.setup_state == "failed"
    assert result.errors == {"apply": "hash failed for [redacted]"}
    assert user is None
    assert setup_state.state == "failed"
    assert setup_state.last_error == "hash failed for [redacted]"
    assert "StrongPass1!" not in repr(result)
    assert "StrongPass1!" not in setup_state.last_error
    assert_no_sensitive_log_values("StrongPass1!")
