# ruff: noqa: PLR1702

import logging
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from satoidc.auth.client_management import (
    ClientMetadataValidationError,
    is_client_disabled,
)
from satoidc.auth.permissions import (
    approve_permission_request,
    deny_permission_request,
    get_admin_dashboard_metrics,
    permission_request_events,
)
from satoidc.auth.security import page_security
from satoidc.enums import PermissionRequestStatusEnum, PermissionsEnum
from satoidc.models import OAuth2Client, Permission
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    CONTENT,
    DIALOG_CLASSES,
    ERROR_TEXT,
    INPUT_CLASSES,
    MUTED_TEXT,
    PAGE,
    PANEL,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    SUCCESS_TEXT,
    TECH_TEXT,
    app_header,
    card,
    empty_state,
    pagination_controls,
    responsive_grid,
)
from satoidc.services.admin_dashboard import (
    PermissionRequestPageFilters,
    list_admin_users_page,
    list_inactive_permissions_page,
    list_oauth_clients_page,
    list_permission_requests_page,
)
from satoidc.services.oauth_clients import (
    delete_oauth_client,
    rotate_oauth_client_secret,
    toggle_oauth_client_status,
    update_oauth_client,
)

router = APIRouter(prefix="/dashboard")
log = logging.getLogger(__name__)

Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/admin")
@page_security(permissions=[PermissionsEnum.ADMIN])
async def dashboard_admin(  # noqa: PLR0912, PLR0915, PLR1702
    session: Session, request: Request
):  # pragma: no cover
    actor_id = UUID(request.session.get("user_id"))
    page_state = {
        "pending": {"page": 1, "page_size": 5},
        "users": {"page": 1, "page_size": 5},
        "clients": {"page": 1, "page_size": 5},
        "inactive": {"page": 1, "page_size": 5},
    }

    async def change_dashboard_page(
        section: str, page: int, page_size: int
    ) -> None:
        page_state[section] = {"page": page, "page_size": page_size}
        await admin_dashboard_content.refresh()

    def inline_empty_state(icon: str, title: str, body: str):
        with ui.column().classes(
            "w-full items-center gap-2 rounded-lg border border-dashed "
            "border-slate-300/80 bg-white/45 p-4 text-center "
            "dark:border-white/10 dark:bg-slate-950/30"
        ):
            ui.icon(icon).classes("text-3xl text-sky-500 dark:text-sky-300")
            ui.label(title).classes("font-semibold")
            ui.label(body).classes(f"text-sm {MUTED_TEXT}")

    def page_errors(errors: tuple[str, ...]):
        if errors:
            with ui.column().classes(
                "w-full gap-1 rounded-lg border border-red-200/80 "
                "bg-red-50/80 p-3 dark:border-red-900/50 "
                "dark:bg-red-950/30"
            ):
                for error in errors:
                    ui.label(error).classes(f"text-sm {ERROR_TEXT}")

    async def approve_request(permission_request_id: int):
        try:
            permission_request = await approve_permission_request(
                session,
                permission_request_id,
                actor_id=actor_id,
                decision_reason="Approved in admin dashboard",
            )
            await session.commit()
            await permission_request_events.call(
                {
                    "action": "approved",
                    "permission_request_id": permission_request.id,
                    "permission_type": str(
                        permission_request.permission_type
                    ),
                    "requester_id": str(permission_request.requester_id),
                }
            )
            ui.notify("Developer access approved.", type="positive")
        except Exception as exc:
            await session.rollback()
            log.exception(
                "Admin permission approval failed",
                extra={
                    "event_name": "admin.permission_approval_failed",
                    "component": "admin_dashboard",
                    "outcome": "failed",
                    "reason": exc.__class__.__name__,
                    "permission_request_id": permission_request_id,
                },
            )
            ui.notify("Permission approval failed.", type="negative")

    def deny_dialog(permission_request_id: int):
        with ui.dialog() as dialog, ui.card().classes(
            "w-[calc(100vw-2rem)] max-w-lg gap-4"
        ):
            ui.label("Deny permission request").classes(
                "text-xl font-semibold"
            )
            reason = ui.textarea("Decision note").classes(INPUT_CLASSES)

            async def deny_request():
                try:
                    permission_request = await deny_permission_request(
                        session,
                        permission_request_id,
                        actor_id=actor_id,
                        decision_reason=reason.value,
                    )
                    await session.commit()
                    await permission_request_events.call(
                        {
                            "action": "denied",
                            "permission_request_id": permission_request.id,
                            "permission_type": str(
                                permission_request.permission_type
                            ),
                            "requester_id": str(
                                permission_request.requester_id
                            ),
                        }
                    )
                    ui.notify("Permission request denied.", type="warning")
                    dialog.close()
                except Exception as exc:
                    await session.rollback()
                    log.exception(
                        "Admin permission denial failed",
                        extra={
                            "event_name": "admin.permission_denial_failed",
                            "component": "admin_dashboard",
                            "outcome": "failed",
                            "reason": exc.__class__.__name__,
                            "permission_request_id": permission_request_id,
                        },
                    )
                    ui.notify("Permission denial failed.", type="negative")

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Deny", icon="close", on_click=deny_request).classes(
                    SECONDARY_BUTTON_CLASSES
                )
        dialog.open()

    @ui.refreshable
    async def admin_dashboard_content():  # noqa: PLR0912, PLR0914, PLR0915
        session.expire_all()
        metrics = await get_admin_dashboard_metrics(session)
        pending_state = page_state["pending"]
        pending_requests_page = await list_permission_requests_page(
            session,
            filters=PermissionRequestPageFilters(
                status=PermissionRequestStatusEnum.PENDING
            ),
            page=pending_state["page"],
            page_size=pending_state["page_size"],
        )
        pending_requests = pending_requests_page.items
        recent_decisions = await session.scalars(
            select(Permission)
            .options(selectinload(Permission.user))
            .where(Permission.permission_type == PermissionsEnum.DEVELOPER)
            .order_by(Permission.created_at.desc())
            .limit(5)
        )
        recent_permissions = list(recent_decisions.all())
        users_state = page_state["users"]
        clients_state = page_state["clients"]
        inactive_state = page_state["inactive"]
        users_page = await list_admin_users_page(
            session,
            page=users_state["page"],
            page_size=users_state["page_size"],
        )
        clients_page = await list_oauth_clients_page(
            session,
            page=clients_state["page"],
            page_size=clients_state["page_size"],
        )
        inactive_permissions_page = await list_inactive_permissions_page(
            session,
            page=inactive_state["page"],
            page_size=inactive_state["page_size"],
        )
        users = users_page.items
        clients = clients_page.items
        inactive_permissions = inactive_permissions_page.items

        with ui.column().classes(f"{CONTENT} gap-6"):
            with ui.row().classes(
                "w-full items-center justify-between gap-3 max-sm:flex-col "
                "max-sm:items-stretch"
            ):
                with ui.column().classes("gap-1"):
                    ui.label("Operations").classes("text-2xl font-bold")
                    ui.label(
                        "Review access requests and monitor active platform "
                        "state."
                    ).classes(MUTED_TEXT)
                ui.button(
                    f"{metrics.pending_requests} pending",
                    icon="notifications",
                ).classes(SECONDARY_BUTTON_CLASSES)

            with responsive_grid(3, "gap-4"):
                for label, value, icon in [
                    (
                        "Pending requests",
                        metrics.pending_requests,
                        "pending_actions",
                    ),
                    ("Total users", metrics.total_users, "group"),
                    (
                        "Developer access",
                        metrics.developer_access_users,
                        "code",
                    ),
                    (
                        "OAuth clients",
                        metrics.registered_clients,
                        "app_registration",
                    ),
                    (
                        "New clients, 7d",
                        metrics.recently_created_clients,
                        "update",
                    ),
                    (
                        "Inactive permissions",
                        metrics.inactive_permissions,
                        "block",
                    ),
                ]:
                    with ui.column().classes(f"{PANEL} p-4 gap-2"):
                        with ui.row().classes(
                            "items-center justify-between w-full"
                        ):
                            ui.label(label).classes(f"text-sm {MUTED_TEXT}")
                            ui.icon(icon).classes("text-sky-500")
                        ui.label(str(value)).classes("text-3xl font-bold")

            with card("gap-4"):
                with ui.row().classes(
                    "w-full items-center justify-between gap-3"
                ):
                    ui.label("Pending Permission Requests").classes(
                        "text-lg font-semibold"
                    )
                    ui.chip(
                        str(pending_requests_page.total),
                        icon="notifications",
                    )
                page_errors(pending_requests_page.errors)
                if pending_requests:
                    with ui.list().classes("w-full"):
                        for permission_request in pending_requests:
                            requester = permission_request.requester
                            identity = (
                                requester.login
                                or requester.email
                                or requester.nickname
                                or str(requester.id)
                            )
                            with ui.item().classes(
                                "rounded-lg border border-slate-200/70 "
                                "dark:border-white/10 my-2"
                            ):
                                with ui.item_section().props("avatar"):
                                    ui.icon("person")
                                with ui.item_section():
                                    ui.item_label(identity)
                                    ui.item_label(
                                        permission_request.reason
                                        or "No requester note"
                                    ).props("caption")
                                with ui.item_section():
                                    ui.item_label(
                                        str(
                                            permission_request.permission_type
                                        )
                                    )
                                    ui.item_label("permission").props(
                                        "caption"
                                    )
                                with ui.item_section().props("side"):
                                    with ui.row().classes(
                                        "items-center gap-2 flex-wrap "
                                        "justify-end"
                                    ):
                                        request_id = permission_request.id

                                        async def approve_current(
                                            request_id=request_id,
                                        ):
                                            await approve_request(request_id)

                                        def deny_current(
                                            request_id=request_id,
                                        ):
                                            deny_dialog(request_id)

                                        ui.button(
                                            "Approve",
                                            icon="check",
                                            on_click=approve_current,
                                        ).classes(PRIMARY_BUTTON_CLASSES)
                                        ui.button(
                                            "Deny",
                                            icon="close",
                                            on_click=deny_current,
                                        ).classes(SECONDARY_BUTTON_CLASSES)
                else:
                    inline_empty_state(
                        icon="task_alt",
                        title="No pending requests",
                        body=(
                            "Developer access requests will appear here when "
                            "users submit them from profile."
                        ),
                    )
                pagination_controls(
                    pending_requests_page,
                    label="Pending requests",
                    on_change=lambda page, page_size: change_dashboard_page(
                        "pending", page, page_size
                    ),
                )

            with responsive_grid(2, "gap-6"):
                with card("gap-4"):
                    ui.label("Recent Developer Grants").classes(
                        "text-lg font-semibold"
                    )
                    if recent_permissions:
                        with ui.list().classes("w-full"):
                            for permission in recent_permissions:
                                user = permission.user
                                ui.item_label(
                                    user.login
                                    or user.email
                                    or user.nickname
                                    or str(user.id)
                                )
                                ui.item_label(
                                    permission.reason or "Developer access"
                                ).props("caption")
                    else:
                        ui.label("No developer approvals yet.").classes(
                            MUTED_TEXT
                        )

                with card("gap-4"):
                    with ui.row().classes(
                        "w-full items-center justify-between gap-3"
                    ):
                        ui.label("Users").classes("text-lg font-semibold")
                        ui.chip(str(users_page.total), icon="group")
                    page_errors(users_page.errors)
                    if users:
                        with ui.list().classes("w-full"):
                            for user in users:
                                ui.item_label(
                                    user.login
                                    or user.email
                                    or user.nickname
                                    or str(user.id)
                                )
                                ui.item_label(
                                    "active" if user.is_active else "inactive"
                                ).props("caption")
                    else:
                        inline_empty_state(
                            icon="group",
                            title="No users registered",
                            body="Registered accounts will appear here.",
                        )
                    pagination_controls(
                        users_page,
                        label="Users",
                        on_change=lambda page, page_size: (
                            change_dashboard_page(
                                "users", page, page_size
                            )
                        ),
                    )

                with card("gap-4"):
                    with ui.row().classes(
                        "w-full items-center justify-between gap-3"
                    ):
                        ui.label("OAuth Clients").classes(
                            "text-lg font-semibold"
                        )
                        ui.chip(
                            str(clients_page.total),
                            icon="app_registration",
                        )
                    page_errors(clients_page.errors)
                    if clients:
                        with ui.list().classes("w-full"):
                            for client in clients:
                                metadata = client.client_metadata or {}
                                ui.item_label(
                                    metadata.get("client_name")
                                    or client.client_id
                                )
                                ui.item_label(client.client_id).props(
                                    "caption"
                                )
                    else:
                        inline_empty_state(
                            icon="app_registration",
                            title="No clients registered",
                            body=(
                                "OAuth2 client registrations will appear "
                                "here."
                            ),
                        )
                    pagination_controls(
                        clients_page,
                        label="OAuth clients",
                        on_change=lambda page, page_size: (
                            change_dashboard_page(
                                "clients", page, page_size
                            )
                        ),
                    )

                with card("gap-4"):
                    with ui.row().classes(
                        "w-full items-center justify-between gap-3"
                    ):
                        ui.label("Inactive Permissions").classes(
                            "text-lg font-semibold"
                        )
                        ui.chip(
                            str(inactive_permissions_page.total),
                            icon="block",
                        )
                    page_errors(inactive_permissions_page.errors)
                    if inactive_permissions:
                        with ui.list().classes("w-full"):
                            for permission in inactive_permissions:
                                user = permission.user
                                ui.item_label(
                                    user.login
                                    or user.email
                                    or user.nickname
                                    or str(user.id)
                                )
                                ui.item_label(
                                    f"{permission.permission_type}"
                                ).props("caption")
                    else:
                        inline_empty_state(
                            icon="verified",
                            title="No inactive permissions",
                            body="No expired or disabled permissions.",
                        )
                    pagination_controls(
                        inactive_permissions_page,
                        label="Inactive permissions",
                        on_change=lambda page, page_size: (
                            change_dashboard_page(
                                "inactive", page, page_size
                            )
                        ),
                    )

    @permission_request_events.subscribe
    async def _refresh_admin_dashboard(_data: dict):
        await admin_dashboard_content.refresh()

    app_header(
        title="Admin Dashboard",
        user_label="Admin",
        show_brand=False,
    )
    with ui.column().classes(PAGE):
        await admin_dashboard_content()


@router.page("/developer")
@page_security(permissions=[PermissionsEnum.DEVELOPER, PermissionsEnum.ADMIN])
async def dashboard_developer(  # noqa: PLR0915, PLR1702
    session: Session, request: Request
):  # pragma: no cover
    user_id = request.session.get("user_id")
    clients = list(
        (
            await session.scalars(
                select(OAuth2Client).where(
                    OAuth2Client.user_id == UUID(user_id)
                )
            )
        ).all()
    )

    def copy_button(label: str, value: str):
        ui.button(
            label,
            icon="content_copy",
            on_click=lambda value=value: (
                ui.clipboard.write(value),
                ui.notify("Copied to clipboard.", type="positive"),
            ),
        ).classes(SECONDARY_BUTTON_CLASSES)

    def secret_dialog(secret: str):
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Client secret").classes("text-xl font-semibold")
            ui.label(
                "Copy this secret now. It is only shown in this dialog."
            ).classes(MUTED_TEXT)
            ui.label(secret).classes(TECH_TEXT)
            with ui.row().classes("justify-end gap-3 w-full"):
                copy_button("Copy secret", secret)
                ui.button(
                    "Close", icon="close", on_click=dialog.close
                ).classes(PRIMARY_BUTTON_CLASSES)
        dialog.open()

    def edit_client_dialog(client: OAuth2Client):
        metadata = client.client_metadata or {}
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Edit OAuth2 client").classes("text-xl font-semibold")
            client_name = ui.input(
                "Client Name", value=metadata.get("client_name") or ""
            ).classes(INPUT_CLASSES)
            client_uri = ui.input(
                "Client URI", value=metadata.get("client_uri") or ""
            ).props("type=url").classes(INPUT_CLASSES)
            scope = ui.input(
                "Allowed Scope", value=metadata.get("scope") or ""
            ).classes(INPUT_CLASSES)
            redirect_uri = ui.textarea(
                "Redirect URIs",
                value="\n".join(metadata.get("redirect_uris") or []),
            ).props("rows=4").classes(INPUT_CLASSES)
            grant_type = ui.textarea(
                "Allowed Grant Types",
                value="\n".join(metadata.get("grant_types") or []),
            ).props("rows=3").classes(INPUT_CLASSES)
            response_type = ui.textarea(
                "Allowed Response Types",
                value="\n".join(metadata.get("response_types") or []),
            ).props("rows=3").classes(INPUT_CLASSES)
            token_endpoint_auth_method = ui.select(
                options=[
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                ],
                value=metadata.get("token_endpoint_auth_method")
                or "client_secret_basic",
                label="Token Endpoint Auth Method",
            ).classes(INPUT_CLASSES)

            async def save():
                try:
                    generated_secret = await update_oauth_client(
                        session,
                        client,
                        client_name=client_name.value,
                        client_uri=client_uri.value,
                        scope=scope.value,
                        redirect_uri=redirect_uri.value,
                        grant_type=grant_type.value,
                        response_type=response_type.value,
                        token_endpoint_auth_method=(
                            token_endpoint_auth_method.value
                        ),
                    )
                except ClientMetadataValidationError as error:
                    for message in error.messages[:3]:
                        ui.notify(message, type="negative")
                    return
                except Exception as exc:
                    await session.rollback()
                    log.exception(
                        "OAuth client update failed",
                        extra={
                            "event_name": "developer.client_update_failed",
                            "component": "developer_dashboard",
                            "outcome": "failed",
                            "reason": exc.__class__.__name__,
                            "client_id": client.client_id,
                        },
                    )
                    ui.notify("Client update failed.", type="negative")
                    return
                ui.notify("Client updated.", type="positive")
                if generated_secret:
                    secret_dialog(generated_secret)
                else:
                    ui.navigate.to("/dashboard/developer")

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Save", icon="save", on_click=save).classes(
                    PRIMARY_BUTTON_CLASSES
                )
        dialog.open()

    def rotate_secret_dialog(client: OAuth2Client):
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Rotate client secret").classes("text-xl font-semibold")
            ui.label(
                "Existing deployments using the old secret will fail until "
                "they are updated."
            ).classes(MUTED_TEXT)

            async def rotate():
                try:
                    secret = await rotate_oauth_client_secret(session, client)
                except ClientMetadataValidationError as error:
                    ui.notify(error.messages[0], type="negative")
                    return
                except Exception as exc:
                    await session.rollback()
                    log.exception(
                        "OAuth client secret rotation failed",
                        extra={
                            "event_name": (
                                "developer.client_secret_rotation_failed"
                            ),
                            "component": "developer_dashboard",
                            "outcome": "failed",
                            "reason": exc.__class__.__name__,
                            "client_id": client.client_id,
                        },
                    )
                    ui.notify("Secret rotation failed.", type="negative")
                    return
                dialog.close()
                secret_dialog(secret)

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Rotate", icon="sync", on_click=rotate).classes(
                    PRIMARY_BUTTON_CLASSES
                )
        dialog.open()

    async def toggle_client(client: OAuth2Client):
        try:
            await toggle_oauth_client_status(session, client)
            ui.notify("Client status updated.", type="positive")
            ui.navigate.to("/dashboard/developer")
        except Exception as exc:
            await session.rollback()
            log.exception(
                "OAuth client status mutation failed",
                extra={
                    "event_name": "developer.client_status_failed",
                    "component": "developer_dashboard",
                    "outcome": "failed",
                    "reason": exc.__class__.__name__,
                    "client_id": client.client_id,
                },
            )
            ui.notify("Client status update failed.", type="negative")

    def delete_client_dialog(client: OAuth2Client):
        metadata = client.client_metadata or {}
        client_name = metadata.get("client_name") or client.client_id
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Delete OAuth2 client").classes("text-xl font-semibold")
            ui.label(
                f"Delete {client_name}? This removes the registration and "
                "cannot be undone."
            ).classes(MUTED_TEXT)
            confirmation = ui.input(
                f'Type "{client_name}" to confirm'
            ).classes(INPUT_CLASSES)

            async def delete():
                try:
                    await delete_oauth_client(session, client)
                    ui.notify("Client deleted.", type="positive")
                    ui.navigate.to("/dashboard/developer")
                except Exception as exc:
                    await session.rollback()
                    log.exception(
                        "OAuth client deletion failed",
                        extra={
                            "event_name": "developer.client_delete_failed",
                            "component": "developer_dashboard",
                            "outcome": "failed",
                            "reason": exc.__class__.__name__,
                            "client_id": client.client_id,
                        },
                    )
                    ui.notify("Client deletion failed.", type="negative")

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                delete_button = ui.button(
                    "Delete", icon="delete", on_click=delete
                ).props("color=negative").classes(SECONDARY_BUTTON_CLASSES)
                delete_button.bind_enabled_from(
                    confirmation,
                    "value",
                    backward=lambda value: value == client_name,
                )
        dialog.open()

    app_header(
        title="Developer Dashboard",
        user_label="Developer",
        show_brand=False,
    )
    with ui.column().classes(PAGE):
        with ui.column().classes(f"{CONTENT} gap-6"):
            with ui.row().classes(
                "w-full items-center justify-between gap-3 max-sm:flex-col "
                "max-sm:items-stretch"
            ):
                with ui.column().classes("gap-1"):
                    ui.label("OAuth2 Clients").classes("text-2xl font-bold")
                    ui.label(
                        "Manage client registrations and redirect settings."
                    ).classes(MUTED_TEXT)
                ui.button(
                    "New Client",
                    icon="add",
                    on_click=lambda: ui.navigate.to("/create_client"),
                ).classes(PRIMARY_BUTTON_CLASSES)

            columns = [
                {"name": "name", "label": "Name", "field": "name"},
                {
                    "name": "client_id",
                    "label": "Client ID",
                    "field": "client_id",
                },
                {"name": "status", "label": "Status", "field": "status"},
                {
                    "name": "auth_method",
                    "label": "Auth Method",
                    "field": "auth_method",
                },
                {"name": "scope", "label": "Scope", "field": "scope"},
                {
                    "name": "redirect_uris",
                    "label": "Redirect URIs",
                    "field": "redirect_uris",
                },
            ]
            rows = []
            for client in clients:
                metadata = client.client_metadata or {}
                rows.append(
                    {
                        "name": (
                            metadata.get("client_name") or client.client_id
                        ),
                        "client_id": client.client_id,
                        "status": (
                            "disabled"
                            if is_client_disabled(client)
                            else "active"
                        ),
                        "auth_method": metadata.get(
                            "token_endpoint_auth_method", "-"
                        ),
                        "scope": metadata.get("scope", "-"),
                        "redirect_uris": "\n".join(
                            metadata.get("redirect_uris") or []
                        )
                        or "-",
                    }
                )

            with card("gap-4"):
                table = ui.table(columns=columns, rows=rows).classes("w-full")
                table.props("flat bordered wrap-cells")
                with ui.row().classes(
                    "items-center justify-between w-full gap-3 "
                    "max-sm:flex-col "
                    "max-sm:items-stretch"
                ):
                    ui.input("Search").bind_value(table, "filter").classes(
                        f"max-w-sm {INPUT_CLASSES}"
                    ).props("clearable")
                    ui.label(f"{len(rows)} registered clients").classes(
                        f"text-sm {MUTED_TEXT}"
                    )

            if not clients:
                empty_state(
                    icon="app_registration",
                    title="No clients registered",
                    body="Create a client to start an OAuth2/OIDC flow.",
                    action_label="New Client",
                    action_icon="add",
                    on_action=lambda: ui.navigate.to("/create_client"),
                )

            for client in clients:
                metadata = client.client_metadata or {}
                info = client.client_info or {}
                with card("gap-4"):
                    disabled = is_client_disabled(client)
                    with ui.row().classes(
                        "w-full items-center justify-between gap-3 "
                        "max-sm:flex-col max-sm:items-stretch"
                    ):
                        with ui.column().classes("gap-1"):
                            ui.label(
                                metadata.get("client_name") or client.client_id
                            ).classes("text-lg font-semibold")
                            status_text = (
                                "Client disabled"
                                if disabled
                                else "Client active"
                            )
                            status_classes = (
                                MUTED_TEXT if disabled else SUCCESS_TEXT
                            )
                            ui.label(status_text).classes(
                                f"text-sm {status_classes}"
                            )
                        with ui.row().classes("gap-2 flex-wrap justify-end"):
                            copy_button("Copy ID", client.client_id)
                            ui.button(
                                "Edit",
                                icon="edit",
                                on_click=lambda client=client: (
                                    edit_client_dialog(client)
                                ),
                            ).classes(SECONDARY_BUTTON_CLASSES)
                            ui.button(
                                "Rotate secret",
                                icon="sync",
                                on_click=lambda client=client: (
                                    rotate_secret_dialog(client)
                                ),
                            ).classes(SECONDARY_BUTTON_CLASSES)
                            ui.button(
                                "Enable" if disabled else "Disable",
                                icon="toggle_on" if disabled else "block",
                                on_click=lambda client=client: toggle_client(
                                    client
                                ),
                            ).classes(SECONDARY_BUTTON_CLASSES)
                            ui.button(
                                "Delete",
                                icon="delete",
                                on_click=lambda client=client: (
                                    delete_client_dialog(client)
                                ),
                            ).props("color=negative").classes(
                                SECONDARY_BUTTON_CLASSES
                            )
                    with responsive_grid(2, "gap-3"):
                        for key, value in {
                            "Client ID": info.get(
                                "client_id", client.client_id
                            ),
                            "Auth method": metadata.get(
                                "token_endpoint_auth_method", "-"
                            ),
                            "Scope": metadata.get("scope", "-"),
                            "Client URI": metadata.get("client_uri", "-"),
                            "Secret": (
                                "Configured"
                                if client.client_secret
                                else "Public client"
                            ),
                        }.items():
                            with ui.column().classes(f"{PANEL} p-3 gap-1"):
                                ui.label(key).classes(f"text-sm {MUTED_TEXT}")
                                ui.label(str(value)).classes(
                                    TECH_TEXT
                                )
                    redirect_uris = metadata.get("redirect_uris") or []
                    with ui.column().classes("gap-2"):
                        ui.label("Redirect URIs").classes(
                            f"text-sm {MUTED_TEXT}"
                        )
                        if redirect_uris:
                            for uri in redirect_uris:
                                ui.label(uri).classes(
                                    TECH_TEXT
                                )
                        else:
                            ui.label("No redirect URIs configured").classes(
                                f"text-sm {MUTED_TEXT}"
                            )
