from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth import security
from satoidc.enums import PermissionsEnum
from satoidc.models import Permission, User
from satoidc.services.setup_lock import (
    SetupLockDiagnostics,
    SetupLockUnavailableError,
    acquire_setup_lock,
    fail_setup_lock,
    release_setup_lock,
)
from satoidc.validators import (
    is_valid_email,
    is_valid_login,
    is_valid_password,
)


class InteractiveSetupApplyStatus(str, Enum):
    APPLIED = "applied"
    VALIDATION_ERROR = "validation_error"
    ADMIN_EXISTS = "admin_exists"
    LOCK_UNAVAILABLE = "lock_unavailable"
    FAILED = "failed"


@dataclass(frozen=True)
class InteractiveSetupAdminPayload:
    username: str
    email: str
    password: str
    password_confirmation: str


@dataclass(frozen=True)
class InteractiveSetupApplyResult:
    status: InteractiveSetupApplyStatus
    message: str
    errors: dict[str, str]
    user_id: str | None = None
    setup_state: str | None = None
    diagnostics: SetupLockDiagnostics | None = None

    @property
    def applied(self) -> bool:
        return self.status == InteractiveSetupApplyStatus.APPLIED


async def validate_interactive_setup_admin_payload(
    payload: InteractiveSetupAdminPayload,
) -> dict[str, str]:
    errors: dict[str, str] = {}
    username = payload.username.strip().lower()
    email = payload.email.strip().lower()

    if not is_valid_login(username):
        errors["username"] = (
            "Username must be 6-30 lowercase letters and digits."
        )
    if not is_valid_email(email):
        errors["email"] = "Email must be a valid email address."
    if not is_valid_password(payload.password):
        errors["password"] = (
            "Password must be 8-128 chars, with upper/lowercase, digit, and "
            "special char."
        )
    if payload.password != payload.password_confirmation:
        errors["password_confirmation"] = "Password confirmation must match."
    return errors


async def apply_interactive_setup_admin(
    session: AsyncSession,
    payload: InteractiveSetupAdminPayload,
    *,
    actor: str = "interactive-setup",
) -> InteractiveSetupApplyResult:
    result: InteractiveSetupApplyResult | None = None
    errors = await validate_interactive_setup_admin_payload(payload)
    if errors:
        result = InteractiveSetupApplyResult(
            status=InteractiveSetupApplyStatus.VALIDATION_ERROR,
            message="Interactive setup admin payload is invalid.",
            errors=errors,
        )

    username = payload.username.strip().lower()
    email = payload.email.strip().lower()

    if result is None and await _root_or_admin_exists(session):
        result = InteractiveSetupApplyResult(
            status=InteractiveSetupApplyStatus.ADMIN_EXISTS,
            message=(
                "Interactive setup cannot create an initial root user because "
                "a root/admin permission already exists."
            ),
            errors={"admin": "A root/admin user already exists."},
        )
    if result is None and await _identity_exists(
        session, username=username, email=email
    ):
        result = InteractiveSetupApplyResult(
            status=InteractiveSetupApplyStatus.VALIDATION_ERROR,
            message="Interactive setup admin payload is invalid.",
            errors={
                "admin": "Username or email is already assigned to a user."
            },
        )

    if result is None:
        try:
            lock = await acquire_setup_lock(session, actor=actor)
        except SetupLockUnavailableError as exc:
            result = InteractiveSetupApplyResult(
                status=InteractiveSetupApplyStatus.LOCK_UNAVAILABLE,
                message=exc.diagnostics.message,
                errors={"setup_lock": exc.diagnostics.message},
                setup_state=exc.diagnostics.current_state,
                diagnostics=exc.diagnostics,
            )

    if result is None:
        result = await _apply_with_lock(
            session, payload, actor=actor, lock=lock
        )

    return result


async def _apply_with_lock(
    session: AsyncSession,
    payload: InteractiveSetupAdminPayload,
    *,
    actor: str,
    lock,
) -> InteractiveSetupApplyResult:
    username = payload.username.strip().lower()
    email = payload.email.strip().lower()

    try:
        await _ensure_no_admin_or_identity_conflict(
            session, username=username, email=email
        )

        user = User(
            lnurl_pubkey=None,
            email=email,
            login=username,
            password_hash=security.hash_password(payload.password),
            nickname=username,
            is_active=True,
            email_verified=True,
        )
        session.add(user)
        await session.flush()
        session.add(
            Permission(
                user_id=user.id,
                granted_by=None,
                permission_type=PermissionsEnum.ROOT,
                expiration_date=None,
                reason="Initial root bootstrap from interactive setup",
            )
        )
        await session.flush()

        setup_state = await release_setup_lock(
            session,
            lock,
            completed_by=actor,
            config_hash=_payload_config_hash(username=username, email=email),
        )
        return InteractiveSetupApplyResult(
            status=InteractiveSetupApplyStatus.APPLIED,
            message="Interactive setup applied successfully.",
            errors={},
            user_id=str(user.id),
            setup_state=setup_state.state,
        )
    except InteractiveSetupConflictError as exc:
        await session.rollback()
        failed_state = await fail_setup_lock(
            session, lock, error=_sanitize_error(str(exc), payload)
        )
        return InteractiveSetupApplyResult(
            status=InteractiveSetupApplyStatus.ADMIN_EXISTS,
            message=str(exc),
            errors={"admin": str(exc)},
            setup_state=failed_state.state,
        )
    except Exception as exc:
        await session.rollback()
        sanitized_error = _sanitize_error(str(exc), payload)
        failed_state = await fail_setup_lock(
            session, lock, error=sanitized_error
        )
        return InteractiveSetupApplyResult(
            status=InteractiveSetupApplyStatus.FAILED,
            message="Interactive setup apply failed.",
            errors={"apply": sanitized_error},
            setup_state=failed_state.state,
        )


class InteractiveSetupConflictError(RuntimeError):
    pass


async def _ensure_no_admin_or_identity_conflict(
    session: AsyncSession, *, username: str, email: str
) -> None:
    if await _root_or_admin_exists(session):
        raise InteractiveSetupConflictError(
            "A root/admin user already exists."
        )
    if await _identity_exists(session, username=username, email=email):
        raise InteractiveSetupConflictError(
            "Username or email is already assigned to a user."
        )


async def _root_or_admin_exists(session: AsyncSession) -> bool:
    count = await session.scalar(
        select(func.count(Permission.id)).where(
            Permission.permission_type.in_(
                (PermissionsEnum.ROOT, PermissionsEnum.ADMIN)
            ),
            Permission.disabled.is_(False),
        )
    )
    return bool(count)


async def _identity_exists(
    session: AsyncSession, *, username: str, email: str
) -> bool:
    existing_user = await session.scalar(
        select(User.id).where((User.login == username) | (User.email == email))
    )
    return existing_user is not None


def _payload_config_hash(*, username: str, email: str) -> str:
    payload = json.dumps(
        {"admin_email": email, "admin_username": username, "version": 1},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sanitize_error(
    message: str, payload: InteractiveSetupAdminPayload
) -> str:
    sanitized = message or "Unknown setup failure."
    for secret in {payload.password, payload.password_confirmation}:
        if secret:
            sanitized = sanitized.replace(secret, "[redacted]")
    return sanitized
