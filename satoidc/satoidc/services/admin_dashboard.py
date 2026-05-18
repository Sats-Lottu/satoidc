from dataclasses import dataclass
from math import ceil
from typing import Generic, TypeVar
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from satoidc.enums import PermissionRequestStatusEnum, PermissionsEnum
from satoidc.models import OAuth2Client, Permission, PermissionRequest, User

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 100

T = TypeVar("T")


@dataclass(frozen=True)
class PaginationParams:
    page: int = DEFAULT_PAGE
    page_size: int = DEFAULT_PAGE_SIZE


@dataclass(frozen=True)
class PermissionRequestPageFilters:
    status: PermissionRequestStatusEnum | None = None
    permission_type: PermissionsEnum | None = None
    requester_id: UUID | None = None


@dataclass(frozen=True)
class Page(Generic[T]):
    items: list[T]
    page: int
    page_size: int
    total: int
    total_pages: int
    errors: tuple[str, ...] = ()

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    @property
    def has_previous(self) -> bool:
        return self.page > 1 and self.total_pages > 0


def _normalize_pagination(
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> tuple[PaginationParams, tuple[str, ...]]:
    errors: list[str] = []
    normalized_page = page
    normalized_page_size = page_size

    if page < 1:
        normalized_page = DEFAULT_PAGE
        errors.append("page must be greater than or equal to 1")
    if page_size < 1:
        normalized_page_size = DEFAULT_PAGE_SIZE
        errors.append("page_size must be greater than or equal to 1")
    elif page_size > MAX_PAGE_SIZE:
        normalized_page_size = MAX_PAGE_SIZE
        errors.append(
            f"page_size must be less than or equal to {MAX_PAGE_SIZE}"
        )

    return (
        PaginationParams(
            page=normalized_page,
            page_size=normalized_page_size,
        ),
        tuple(errors),
    )


async def _paginate(
    session: AsyncSession,
    *,
    statement: Select[tuple[T]],
    count_statement: Select[tuple[int]],
    page: int,
    page_size: int,
) -> Page[T]:
    params, errors = _normalize_pagination(page, page_size)
    total = int((await session.scalar(count_statement)) or 0)
    result = await session.scalars(
        statement.limit(params.page_size).offset(
            (params.page - 1) * params.page_size
        )
    )
    return Page(
        items=list(result.all()),
        page=params.page,
        page_size=params.page_size,
        total=total,
        total_pages=ceil(total / params.page_size) if total else 0,
        errors=errors,
    )


async def list_admin_users_page(
    session: AsyncSession,
    *,
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> Page[User]:
    return await _paginate(
        session,
        statement=select(User).order_by(
            User.created_at.desc(),
            User.id.desc(),
        ),
        count_statement=select(func.count(User.id)),
        page=page,
        page_size=page_size,
    )


async def list_oauth_clients_page(
    session: AsyncSession,
    *,
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    user_id: UUID | None = None,
) -> Page[OAuth2Client]:
    statement = select(OAuth2Client).order_by(
        OAuth2Client.client_id_issued_at.desc(),
        OAuth2Client.id.desc(),
    )
    count_statement = select(func.count(OAuth2Client.id))
    if user_id is not None:
        statement = statement.where(OAuth2Client.user_id == user_id)
        count_statement = count_statement.where(
            OAuth2Client.user_id == user_id
        )
    return await _paginate(
        session,
        statement=statement,
        count_statement=count_statement,
        page=page,
        page_size=page_size,
    )


async def list_permission_requests_page(
    session: AsyncSession,
    *,
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    filters: PermissionRequestPageFilters | None = None,
) -> Page[PermissionRequest]:
    filters = filters or PermissionRequestPageFilters()
    statement = (
        select(PermissionRequest)
        .options(
            selectinload(PermissionRequest.requester),
            selectinload(PermissionRequest.decider),
        )
        .order_by(
            PermissionRequest.created_at.desc(),
            PermissionRequest.id.desc(),
        )
    )
    count_statement = select(func.count(PermissionRequest.id))
    if filters.status is not None:
        statement = statement.where(PermissionRequest.status == filters.status)
        count_statement = count_statement.where(
            PermissionRequest.status == filters.status
        )
    if filters.permission_type is not None:
        statement = statement.where(
            PermissionRequest.permission_type == filters.permission_type
        )
        count_statement = count_statement.where(
            PermissionRequest.permission_type == filters.permission_type
        )
    if filters.requester_id is not None:
        statement = statement.where(
            PermissionRequest.requester_id == filters.requester_id
        )
        count_statement = count_statement.where(
            PermissionRequest.requester_id == filters.requester_id
        )
    return await _paginate(
        session,
        statement=statement,
        count_statement=count_statement,
        page=page,
        page_size=page_size,
    )


async def list_inactive_permissions_page(
    session: AsyncSession,
    *,
    page: int = DEFAULT_PAGE,
    page_size: int = DEFAULT_PAGE_SIZE,
    permission_type: PermissionsEnum | None = None,
    user_id: UUID | None = None,
) -> Page[Permission]:
    inactive_filter = (Permission.disabled.is_(True)) | (
        Permission.expiration_date <= func.now()
    )
    statement = (
        select(Permission)
        .options(selectinload(Permission.user))
        .where(inactive_filter)
        .order_by(Permission.created_at.desc(), Permission.id.desc())
    )
    count_statement = select(func.count(Permission.id)).where(inactive_filter)
    if permission_type is not None:
        statement = statement.where(
            Permission.permission_type == permission_type
        )
        count_statement = count_statement.where(
            Permission.permission_type == permission_type
        )
    if user_id is not None:
        statement = statement.where(Permission.user_id == user_id)
        count_statement = count_statement.where(Permission.user_id == user_id)
    return await _paginate(
        session,
        statement=statement,
        count_statement=count_statement,
        page=page,
        page_size=page_size,
    )
