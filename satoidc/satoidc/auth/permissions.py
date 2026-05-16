from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from nicegui import Event
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from satoidc.enums import PermissionRequestStatusEnum, PermissionsEnum
from satoidc.models import OAuth2Client, Permission, PermissionRequest, User

DEVELOPER_ACCESS_PERMISSIONS = {
    PermissionsEnum.DEVELOPER,
    PermissionsEnum.ADMIN,
    PermissionsEnum.ROOT,
}
ADMIN_ACCESS_PERMISSIONS = {PermissionsEnum.ADMIN, PermissionsEnum.ROOT}
permission_request_events = Event[dict]()


class PermissionRequestError(Exception):
    """Base error for permission request operations."""


class PermissionRequestNotFound(PermissionRequestError):
    """Raised when a permission request does not exist."""


class PermissionRequestNotAllowed(PermissionRequestError):
    """Raised when a requester already has the requested access."""


@dataclass(frozen=True)
class AdminDashboardMetrics:
    pending_requests: int
    total_users: int
    developer_access_users: int
    registered_clients: int
    recently_created_clients: int
    inactive_permissions: int


def _permission_values(
    permissions: set[PermissionsEnum] | set[str],
) -> set[str]:
    return {str(permission) for permission in permissions}


def has_developer_access(
    permissions: set[PermissionsEnum] | set[str],
) -> bool:
    access_values = _permission_values(DEVELOPER_ACCESS_PERMISSIONS)
    return bool(access_values & _permission_values(permissions))


async def get_active_permissions_for_user(
    session: AsyncSession, user_id: UUID
) -> set[PermissionsEnum]:
    result = await session.scalars(
        select(Permission.permission_type).where(
            Permission.user_id == user_id,
            Permission.disabled.is_(False),
            (Permission.expiration_date > func.now())
            | (Permission.expiration_date.is_(None)),
        )
    )
    return set(result.all())


async def get_latest_permission_request(
    session: AsyncSession,
    requester_id: UUID,
    permission_type: PermissionsEnum = PermissionsEnum.DEVELOPER,
) -> PermissionRequest | None:
    return await session.scalar(
        select(PermissionRequest)
        .where(
            PermissionRequest.requester_id == requester_id,
            PermissionRequest.permission_type == permission_type,
        )
        .order_by(PermissionRequest.created_at.desc())
        .limit(1)
    )


async def create_permission_request(
    session: AsyncSession,
    requester_id: UUID,
    *,
    permission_type: PermissionsEnum = PermissionsEnum.DEVELOPER,
    reason: str | None = None,
) -> PermissionRequest:
    active_permissions = await get_active_permissions_for_user(
        session, requester_id
    )
    if (
        permission_type == PermissionsEnum.DEVELOPER
        and has_developer_access(active_permissions)
    ):
        raise PermissionRequestNotAllowed(
            "Requester already has developer access."
        )

    pending_request = await session.scalar(
        select(PermissionRequest).where(
            PermissionRequest.requester_id == requester_id,
            PermissionRequest.permission_type == permission_type,
            PermissionRequest.status == PermissionRequestStatusEnum.PENDING,
        )
    )
    if pending_request:
        return pending_request

    permission_request = PermissionRequest(
        requester_id=requester_id,
        permission_type=permission_type,
        reason=(reason or "").strip() or None,
    )
    session.add(permission_request)
    await session.flush()
    return permission_request


async def list_permission_requests(
    session: AsyncSession,
    *,
    status: PermissionRequestStatusEnum | None = None,
    limit: int = 50,
) -> list[PermissionRequest]:
    statement = (
        select(PermissionRequest)
        .options(
            selectinload(PermissionRequest.requester),
            selectinload(PermissionRequest.decider),
        )
        .order_by(PermissionRequest.created_at.desc())
        .limit(limit)
    )
    if status:
        statement = statement.where(PermissionRequest.status == status)
    result = await session.scalars(statement)
    return list(result.all())


async def _get_permission_request(
    session: AsyncSession, permission_request_id: int
) -> PermissionRequest:
    permission_request = await session.scalar(
        select(PermissionRequest)
        .options(
            selectinload(PermissionRequest.requester),
            selectinload(PermissionRequest.decider),
        )
        .where(PermissionRequest.id == permission_request_id)
    )
    if permission_request is None:
        raise PermissionRequestNotFound(
            f"Permission request {permission_request_id} was not found."
        )
    return permission_request


async def approve_permission_request(
    session: AsyncSession,
    permission_request_id: int,
    *,
    actor_id: UUID,
    decision_reason: str | None = None,
) -> PermissionRequest:
    permission_request = await _get_permission_request(
        session, permission_request_id
    )
    if permission_request.status != PermissionRequestStatusEnum.PENDING:
        return permission_request

    permission = await session.scalar(
        select(Permission).where(
            Permission.user_id == permission_request.requester_id,
            Permission.permission_type == permission_request.permission_type,
        )
    )
    if permission:
        permission.disabled = False
        permission.expiration_date = None
        permission.granted_by = actor_id
        permission.reason = (
            decision_reason or "Approved permission request"
        ).strip()
        session.add(permission)
    else:
        session.add(
            Permission(
                user_id=permission_request.requester_id,
                granted_by=actor_id,
                permission_type=permission_request.permission_type,
                expiration_date=None,
                reason=(
                    decision_reason or "Approved permission request"
                ).strip(),
            )
        )

    permission_request.status = PermissionRequestStatusEnum.APPROVED
    permission_request.decision_reason = (
        decision_reason or ""
    ).strip() or None
    permission_request.decided_by = actor_id
    permission_request.decided_at = datetime.now(timezone.utc)
    session.add(permission_request)
    await session.flush()
    return permission_request


async def deny_permission_request(
    session: AsyncSession,
    permission_request_id: int,
    *,
    actor_id: UUID,
    decision_reason: str | None = None,
) -> PermissionRequest:
    permission_request = await _get_permission_request(
        session, permission_request_id
    )
    if permission_request.status != PermissionRequestStatusEnum.PENDING:
        return permission_request

    permission_request.status = PermissionRequestStatusEnum.DENIED
    permission_request.decision_reason = (
        decision_reason or ""
    ).strip() or None
    permission_request.decided_by = actor_id
    permission_request.decided_at = datetime.now(timezone.utc)
    session.add(permission_request)
    await session.flush()
    return permission_request


async def cancel_permission_request(
    session: AsyncSession,
    permission_request_id: int,
    *,
    requester_id: UUID,
) -> PermissionRequest:
    permission_request = await _get_permission_request(
        session, permission_request_id
    )
    if (
        permission_request.requester_id != requester_id
        or permission_request.status != PermissionRequestStatusEnum.PENDING
    ):
        return permission_request

    permission_request.status = PermissionRequestStatusEnum.CANCELLED
    session.add(permission_request)
    await session.flush()
    return permission_request


async def get_pending_permission_request_count(
    session: AsyncSession,
) -> int:
    count = await session.scalar(
        select(func.count(PermissionRequest.id)).where(
            PermissionRequest.status == PermissionRequestStatusEnum.PENDING
        )
    )
    return int(count or 0)


async def get_admin_dashboard_metrics(
    session: AsyncSession,
) -> AdminDashboardMetrics:
    pending_requests = await get_pending_permission_request_count(session)
    total_users = await session.scalar(select(func.count(User.id)))
    developer_access_users = await session.scalar(
        select(func.count(distinct(Permission.user_id))).where(
            Permission.permission_type.in_(DEVELOPER_ACCESS_PERMISSIONS),
            Permission.disabled.is_(False),
            (Permission.expiration_date > func.now())
            | (Permission.expiration_date.is_(None)),
        )
    )
    registered_clients = await session.scalar(
        select(func.count(OAuth2Client.id))
    )
    recent_cutoff = int(
        (datetime.now(timezone.utc) - timedelta(days=7)).timestamp()
    )
    recently_created_clients = await session.scalar(
        select(func.count(OAuth2Client.id)).where(
            OAuth2Client.client_id_issued_at >= recent_cutoff
        )
    )
    inactive_permissions = await session.scalar(
        select(func.count(Permission.id)).where(
            (Permission.disabled.is_(True))
            | (Permission.expiration_date <= func.now())
        )
    )
    return AdminDashboardMetrics(
        pending_requests=int(pending_requests or 0),
        total_users=int(total_users or 0),
        developer_access_users=int(developer_access_users or 0),
        registered_clients=int(registered_clients or 0),
        recently_created_clients=int(recently_created_clients or 0),
        inactive_permissions=int(inactive_permissions or 0),
    )
