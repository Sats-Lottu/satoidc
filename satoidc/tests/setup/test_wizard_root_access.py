from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import setup_wizard.get_root as get_root_module
import setup_wizard.routes as routes_module
from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission, SetupState
from setup_wizard.apply import (
    InteractiveSetupAdminPayload,
    InteractiveSetupApplyResult,
    InteractiveSetupApplyStatus,
)
from setup_wizard.get_root import (
    authenticate_root_user,
    authenticate_setup_admin_user,
    database_schema_ready,
    exists_root_user,
    exists_setup_admin_user,
    has_active_root_permission,
    has_active_setup_admin_permission,
    parse_root_user_id,
    setup_completed,
)
from setup_wizard.routes import (
    SETUP_ROOT_USER_ID_KEY,
    apply_initial_root_setup_form,
    high_impact_reconfiguration_names,
    initial_root_form_state_from_result,
    initial_root_review_from_payload,
    set_root,
    setup_reconfiguration_fields,
    stored_root_has_access,
)

pytestmark = pytest.mark.setup


def test_setup_wizard_parses_root_user_ids():
    user_id = uuid4()

    assert parse_root_user_id(user_id.hex) == user_id
    assert parse_root_user_id(str(user_id)) == user_id
    assert parse_root_user_id(user_id) == user_id
    assert parse_root_user_id(None) is None
    assert parse_root_user_id("not-a-uuid") is None


async def test_setup_wizard_detects_missing_root_user(db_session):
    assert await exists_root_user() is False


async def test_setup_wizard_detects_ready_database_schema(db_session):
    assert await database_schema_ready() is True


async def test_setup_wizard_detects_missing_setup_state(db_session):
    assert await setup_completed() is False


async def test_setup_wizard_detects_incomplete_setup_state(db_session):
    db_session.add(SetupState(state="failed", last_error="retryable"))
    await db_session.commit()

    assert await setup_completed() is False


async def test_setup_wizard_detects_completed_setup_state(db_session):
    db_session.add(SetupState(state="completed", completed_by="system"))
    await db_session.commit()

    assert await setup_completed() is True


async def test_setup_wizard_handles_missing_database_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    database_path = tmp_path / "empty.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{database_path.as_posix()}"
    )

    async def empty_get_session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    monkeypatch.setattr(get_root_module, "get_session", empty_get_session)

    try:
        assert await database_schema_ready() is False
        assert await exists_root_user() is False
    finally:
        await engine.dispose()


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
    assert await exists_setup_admin_user() is True


async def test_setup_wizard_detects_existing_admin_user(
    db_session, make_user
):
    user = await make_user()
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ADMIN,
            expiration_date=None,
            reason="test admin user",
        )
    )
    await db_session.commit()

    assert await exists_root_user() is False
    assert await exists_setup_admin_user() is True


async def test_setup_wizard_authenticates_active_root_user(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
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

    authenticated = await authenticate_root_user(
        db_session, user.login, "StrongPass1!"
    )

    assert authenticated is not None
    assert authenticated.id == user.id
    assert await has_active_root_permission(db_session, user.id) is True


async def test_setup_wizard_authenticates_root_by_email(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
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

    authenticated = await authenticate_root_user(
        db_session, user.email.upper(), "StrongPass1!"
    )

    assert authenticated is not None
    assert authenticated.id == user.id


async def test_setup_wizard_authenticates_admin_for_reconfiguration(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ADMIN,
            expiration_date=None,
            reason="test admin user",
        )
    )
    await db_session.commit()

    authenticated = await authenticate_setup_admin_user(
        db_session, user.email.upper(), "StrongPass1!"
    )

    assert authenticated is not None
    assert authenticated.id == user.id
    assert (
        await has_active_setup_admin_permission(db_session, user.id) is True
    )
    assert await has_active_root_permission(db_session, user.id) is False


async def test_setup_wizard_rejects_non_root_credentials(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))

    authenticated = await authenticate_root_user(
        db_session, user.login, "StrongPass1!"
    )

    assert authenticated is None
    assert await has_active_root_permission(db_session, user.id) is False


async def test_setup_wizard_rejects_invalid_root_credentials(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
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

    authenticated = await authenticate_root_user(
        db_session, user.email, "WrongPass1!"
    )

    assert authenticated is None


async def test_setup_wizard_rejects_expired_root_permission(
    db_session, make_user
):
    user = await make_user(password_hash=hash_password("StrongPass1!"))
    db_session.add(
        Permission(
            user_id=user.id,
            granted_by=None,
            permission_type=PermissionsEnum.ROOT,
            expiration_date=datetime.now(timezone.utc)
            - timedelta(minutes=1),
            reason="expired root user",
        )
    )
    await db_session.commit()

    authenticated = await authenticate_root_user(
        db_session, user.login, "StrongPass1!"
    )

    assert authenticated is None
    assert await has_active_root_permission(db_session, user.id) is False


async def test_setup_wizard_keeps_valid_root_session(db_session, make_user):
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
    request = SimpleNamespace(session={SETUP_ROOT_USER_ID_KEY: user.id.hex})

    assert await stored_root_has_access(db_session, request) is True
    assert request.session[SETUP_ROOT_USER_ID_KEY] == user.id.hex


async def test_setup_wizard_clears_invalid_root_session(db_session):
    request = SimpleNamespace(session={SETUP_ROOT_USER_ID_KEY: "invalid"})

    assert await stored_root_has_access(db_session, request) is False
    assert SETUP_ROOT_USER_ID_KEY not in request.session


async def test_setup_wizard_blocks_public_root_creation_when_completed(
    monkeypatch: pytest.MonkeyPatch,
):
    rendered = []

    async def schema_ready():
        return True

    async def completed():
        return True

    async def no_root_user():
        return False

    monkeypatch.setattr(
        routes_module.ui, "add_head_html", lambda *a, **k: None
    )
    monkeypatch.setattr(routes_module, "database_schema_ready", schema_ready)
    monkeypatch.setattr(routes_module, "setup_completed", completed)
    monkeypatch.setattr(
        routes_module,
        "exists_setup_admin_user",
        no_root_user,
    )
    monkeypatch.setattr(
        routes_module,
        "render_completed_setup_locked",
        lambda: rendered.append("locked"),
    )
    monkeypatch.setattr(
        routes_module,
        "render_initial_root_setup",
        lambda request: rendered.append("initial"),
    )

    await set_root(SimpleNamespace(session={}, query_params={}))

    assert rendered == ["locked"]


async def test_setup_wizard_allows_public_root_creation_when_not_completed(
    monkeypatch: pytest.MonkeyPatch,
):
    rendered = []

    async def schema_ready():
        return True

    async def incomplete():
        return False

    async def no_root_user():
        return False

    monkeypatch.setattr(
        routes_module.ui, "add_head_html", lambda *a, **k: None
    )
    monkeypatch.setattr(routes_module, "database_schema_ready", schema_ready)
    monkeypatch.setattr(routes_module, "setup_completed", incomplete)
    monkeypatch.setattr(
        routes_module,
        "exists_setup_admin_user",
        no_root_user,
    )
    monkeypatch.setattr(
        routes_module,
        "render_initial_root_setup",
        lambda request: rendered.append("initial"),
    )

    await set_root(SimpleNamespace(session={}, query_params={}))

    assert rendered == ["initial"]


async def test_initial_root_form_calls_interactive_apply_service(
    monkeypatch: pytest.MonkeyPatch,
):
    captured = {}
    fake_session = object()

    @asynccontextmanager
    async def fake_setup_session():
        yield fake_session

    async def fake_apply_service(session, payload, *, actor):
        captured["session"] = session
        captured["payload"] = payload
        captured["actor"] = actor
        return InteractiveSetupApplyResult(
            status=InteractiveSetupApplyStatus.APPLIED,
            message="Interactive setup applied successfully.",
            errors={},
            user_id=str(uuid4()),
            setup_state="completed",
        )

    monkeypatch.setattr(routes_module, "setup_session", fake_setup_session)
    monkeypatch.setattr(
        routes_module,
        "apply_interactive_setup_admin",
        fake_apply_service,
    )

    result = await apply_initial_root_setup_form(
        username="rootadm",
        email="root@example.com",
        password="StrongPass1!",
        password_confirmation="StrongPass1!",
    )

    assert result.status == InteractiveSetupApplyStatus.APPLIED
    assert captured["session"] is fake_session
    assert captured["actor"] == "interactive-setup"
    assert captured["payload"] == InteractiveSetupAdminPayload(
        username="rootadm",
        email="root@example.com",
        password="StrongPass1!",
        password_confirmation="StrongPass1!",
    )


def test_initial_root_form_state_marks_success_as_completed():
    result = InteractiveSetupApplyResult(
        status=InteractiveSetupApplyStatus.APPLIED,
        message="Interactive setup applied successfully.",
        errors={},
        user_id=str(uuid4()),
        setup_state="completed",
    )

    state = initial_root_form_state_from_result(result)

    assert state == {"errors": {}, "completed": True, "message": ""}


def test_initial_root_form_state_preserves_validation_errors_without_secret():
    result = InteractiveSetupApplyResult(
        status=InteractiveSetupApplyStatus.VALIDATION_ERROR,
        message="Interactive setup admin payload is invalid.",
        errors={
            "password": (
                "Password must be 8-128 chars, with upper/lowercase, digit, "
                "and special char."
            )
        },
    )

    state = initial_root_form_state_from_result(result)

    assert state["completed"] is False
    assert state["message"] == "Interactive setup admin payload is invalid."
    assert "StrongPass1!" not in repr(state)
    assert "password" in state["errors"]


def test_initial_root_form_state_shows_lock_error():
    result = InteractiveSetupApplyResult(
        status=InteractiveSetupApplyStatus.LOCK_UNAVAILABLE,
        message="Setup is locked by another setup attempt.",
        errors={"setup_lock": "Setup is locked by another setup attempt."},
        setup_state="applying",
    )

    state = initial_root_form_state_from_result(result)

    assert state["completed"] is False
    assert state["message"] == "Setup is locked by another setup attempt."
    assert state["errors"] == {
        "setup_lock": "Setup is locked by another setup attempt."
    }


def test_initial_root_review_normalizes_and_masks_secret():
    payload = InteractiveSetupAdminPayload(
        username=" RootAdm ",
        email=" ROOT@Example.COM ",
        password="StrongPass1!",
        password_confirmation="StrongPass1!",
    )

    review = initial_root_review_from_payload(payload)

    assert review == {
        "username": "rootadm",
        "email": "root@example.com",
        "password": "********",
    }
    assert "StrongPass1!" not in repr(review)


def test_setup_reconfiguration_fields_lock_env_and_mask_secrets():
    fields = setup_reconfiguration_fields(
        {
            "SATOIDC_ISSUER": "https://issuer.example.com",
            "SATOIDC_SECRET_KEY": "super-secret-value",
            "SATOIDC_SMTP_PASSWORD_FILE": "/run/secrets/smtp",
        }
    )

    by_name = {field["name"]: field for field in fields}

    assert by_name["OAUTH2_JWT_ISS"]["locked"] is True
    assert by_name["OAUTH2_JWT_ISS"]["high_impact"] is True
    assert (
        by_name["OAUTH2_JWT_ISS"]["display_value"]
        == "https://issuer.example.com"
    )
    assert by_name["SESSION_MIDDLEWARE_SECRET_KEY"]["display_value"] == (
        "********"
    )
    assert by_name["SMTP_PASSWORD"]["source"] == "SATOIDC_SMTP_PASSWORD_FILE"
    assert by_name["SMTP_PASSWORD"]["display_value"] == "********"
    assert "super-secret-value" not in repr(fields)


def test_setup_reconfiguration_fields_marks_safe_unlocked_values_editable(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("SATOIDC_ISSUER", "https://ci.example.com")
    monkeypatch.setenv("OIDC_SIGNING_BACKEND", "database")

    fields = setup_reconfiguration_fields({})
    by_name = {field["name"]: field for field in fields}

    assert by_name["SERVICE_NAME"]["editable"] is True
    assert by_name["SERVICE_NAME"]["key"] == "instance_name"
    assert by_name["OAUTH2_JWT_ISS"]["editable"] is True
    assert by_name["OAUTH2_JWT_ISS"]["high_impact"] is True
    assert by_name["OIDC_SIGNING_BACKEND"]["editable"] is True
    assert by_name["OIDC_SIGNING_BACKEND"]["high_impact"] is True
    assert by_name["SESSION_MIDDLEWARE_SECRET_KEY"]["editable"] is False


def test_high_impact_reconfiguration_names_only_lists_editable_critical():
    fields = setup_reconfiguration_fields(
        {
            "SATOIDC_ISSUER": "https://issuer.example.com",
            "OIDC_SIGNING_BACKEND": "database",
        }
    )

    assert high_impact_reconfiguration_names(fields) == [
        "EMAIL_PUBLIC_BASE_URL",
        "OAUTH2_TOKEN_EXPIRES_IN",
    ]
