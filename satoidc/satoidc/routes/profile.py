# ruff: noqa: PLR1702

from typing import Annotated
from uuid import UUID

import segno
from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, with_loader_criteria

from satoidc.auth.lnurl import lnurl_auth_events, url_encode
from satoidc.auth.permissions import (
    PermissionRequestNotAllowed,
    create_permission_request,
    get_latest_permission_request,
    has_developer_access,
    permission_request_events,
)
from satoidc.auth.security import hash_password, verify_password
from satoidc.enums import PermissionRequestStatusEnum, PermissionsEnum
from satoidc.models import LnurlAuthChallenge, Permission, User
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    DIALOG_CLASSES,
    ERROR_TEXT,
    INPUT_CLASSES,
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    SUCCESS_TEXT,
    TECH_TEXT,
    card,
    footer,
    page_shell,
    responsive_grid,
)
from satoidc.settings import ENV
from satoidc.validators import (
    is_valid_email,
    is_valid_nickname,
    is_valid_password,
)

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


def _field_row(
    label: str,
    value: str,
    action_label: str,
    icon: str,
    on_action,
):  # pragma: no cover
    with ui.row().classes(
        "w-full items-center justify-between gap-3 max-sm:flex-col "
        "max-sm:items-stretch"
    ):
        with ui.column().classes("gap-1"):
            ui.label(label).classes(f"text-sm {MUTED_TEXT}")
            ui.label(value).classes("text-base break-all")
        ui.button(
            action_label,
            icon=icon,
            on_click=on_action,
        ).classes(SECONDARY_BUTTON_CLASSES)


def _detail_row(label: str, value: str):  # pragma: no cover
    with ui.column().classes("gap-1"):
        ui.label(label).classes(f"text-sm {MUTED_TEXT}")
        ui.label(value).classes(TECH_TEXT)


@ui.page("/profile")
async def profile(  # noqa: PLR0912, PLR0915, PLR1702
    session: Session, request: Request
):  # pragma: no cover
    user_id = request.session.get("user_id")
    user = await session.scalar(
        select(User)
        .options(
            selectinload(User.permissions),
            with_loader_criteria(
                Permission,
                lambda cls: (
                    (cls.disabled.is_(False))
                    & (
                        (cls.expiration_date > func.now())
                        | (cls.expiration_date.is_(None))
                    )
                ),
                include_aliases=True,
            ),
        )
        .where(User.id == UUID(user_id))
    )
    permissions = {perm.permission_type for perm in user.permissions}
    latest_developer_request = await get_latest_permission_request(
        session, user.id, PermissionsEnum.DEVELOPER
    )
    wallet_state = "Linked" if user.lnurl_pubkey else "Not linked"
    password_state = "Configured" if user.password_hash else "Not configured"
    developer_state = (
        "Enabled" if has_developer_access(permissions) else "Not enabled"
    )
    created_at = (
        user.created_at.strftime("%Y-%m-%d %H:%M UTC")
        if user.created_at
        else "-"
    )

    def refresh_profile():
        ui.navigate.to("/profile")

    def nickname_dialog():
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Change nickname").classes("text-xl font-semibold")
            nickname = ui.input("Nickname", value=user.nickname or "").classes(
                INPUT_CLASSES
            )

            async def save():
                value = (nickname.value or "").strip()
                if not is_valid_nickname(value):
                    ui.notify("Invalid nickname format.", type="negative")
                    return
                user.nickname = value or "Satoshi"
                session.add(user)
                await session.commit()
                ui.notify("Nickname updated.", type="positive")
                refresh_profile()

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Save", icon="save", on_click=save).classes(
                    PRIMARY_BUTTON_CLASSES
                )
        dialog.open()

    def email_dialog():
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Change email").classes("text-xl font-semibold")
            email = (
                ui
                .input("Email", value=user.email or "")
                .props("type=email")
                .classes(INPUT_CLASSES)
            )

            async def save():
                value = (email.value or "").strip().lower()
                if not is_valid_email(value):
                    ui.notify("Invalid email address.", type="negative")
                    return
                existing_user = await session.scalar(
                    select(User).where(
                        User.email == value,
                        User.id != user.id,
                    )
                )
                if existing_user:
                    ui.notify("Email is already in use.", type="negative")
                    return
                user.email = value
                session.add(user)
                await session.commit()
                ui.notify("Email updated.", type="positive")
                refresh_profile()

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Save", icon="save", on_click=save).classes(
                    PRIMARY_BUTTON_CLASSES
                )
        dialog.open()

    def password_dialog():
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Change password").classes("text-xl font-semibold")
            if user.password_hash:
                current_password = ui.input(
                    "Current password",
                    password=True,
                    password_toggle_button=True,
                ).classes(INPUT_CLASSES)
            else:
                current_password = None
                ui.label(
                    "This account does not currently have a password."
                ).classes(MUTED_TEXT)
            new_password = ui.input(
                "New password", password=True, password_toggle_button=True
            ).classes(INPUT_CLASSES)
            confirm_password = ui.input(
                "Confirm new password",
                password=True,
                password_toggle_button=True,
            ).classes(INPUT_CLASSES)
            ui.label(
                "Use 8-128 characters with uppercase, lowercase, a number, "
                "and a special character."
            ).classes(f"text-sm {MUTED_TEXT}")

            async def save():
                if current_password and not verify_password(
                    current_password.value or "", user.password_hash
                ):
                    ui.notify(
                        "Current password is incorrect.", type="negative"
                    )
                    return
                if not is_valid_password(new_password.value or ""):
                    ui.notify("New password is too weak.", type="negative")
                    return
                if new_password.value != confirm_password.value:
                    ui.notify("Passwords do not match.", type="negative")
                    return
                user.password_hash = hash_password(new_password.value)
                session.add(user)
                await session.commit()
                ui.notify("Password updated.", type="positive")
                refresh_profile()

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Save", icon="save", on_click=save).classes(
                    PRIMARY_BUTTON_CLASSES
                )
        dialog.open()

    def unlink_wallet_dialog():
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Unlink wallet").classes("text-xl font-semibold")
            ui.label(
                "This removes the LNURL public key from your account. "
                "Password login remains available if configured."
            ).classes(MUTED_TEXT)
            if not user.password_hash:
                ui.label(
                    "Set a password before unlinking the only wallet login "
                    "method."
                ).classes(ERROR_TEXT)

            async def unlink():
                if not user.password_hash:
                    ui.notify(
                        "Set a password before unlinking this wallet.",
                        type="negative",
                    )
                    return
                user.lnurl_pubkey = None
                session.add(user)
                await session.commit()
                ui.notify("Wallet unlinked.", type="positive")
                refresh_profile()

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button(
                    "Unlink wallet", icon="link_off", on_click=unlink
                ).classes(SECONDARY_BUTTON_CLASSES)
        dialog.open()

    class LNURLWalletLinkDialog:
        def __init__(self, action_label: str):
            self.action_label = action_label
            self.k1 = None

        async def refresh_qrcode(self):
            challenge = LnurlAuthChallenge(action="link", user_id=user.id)
            session.add(challenge)
            await session.commit()
            await session.refresh(challenge)
            self.k1 = challenge.k1
            self.qrcode.refresh()

        @ui.refreshable_method
        def qrcode(self):
            if not self.k1:
                ui.label("Preparing wallet link...").classes(MUTED_TEXT)
                return
            lnurl_auth = url_encode(
                f"{request.base_url}auth/lnurl/callback?"
                f"tag=login&k1={self.k1}&action=link"
            )
            qrcode = segno.make_qr(lnurl_auth, error="l")
            ui.label(self.action_label).classes("text-lg font-semibold")
            with ui.link(target=f"lightning:{lnurl_auth}").tooltip(
                "Open in Lightning Wallet"
            ):
                ui.image(qrcode.svg_data_uri(light="white", border=1)).classes(
                    "w-64 h-64"
                ).tooltip("Scan with your Lightning Wallet")
            ui.label(lnurl_auth).classes(
                "mt-2 w-full break-all text-xs text-center "
                "text-slate-600 dark:text-slate-400"
            ).on("click", lambda e: ui.clipboard.write(lnurl_auth)).on(
                "click",
                lambda e: ui.notify(
                    "LNURL copied to clipboard.", type="positive"
                ),
            ).tooltip("Click to copy")

    def wallet_link_dialog():
        action_label = (
            "Relink Lightning wallet"
            if user.lnurl_pubkey
            else ("Link Lightning wallet")
        )
        wallet_link = LNURLWalletLinkDialog(action_label)
        ui.timer(
            ENV.LNURL_K1_TTL_SECONDS,
            wallet_link.refresh_qrcode,
        )
        ui.timer(0.1, wallet_link.refresh_qrcode, once=True)

        @lnurl_auth_events.subscribe
        async def _event_handler(data: dict):
            if data.get("k1") == wallet_link.k1:
                ui.notify("Wallet linked.", type="positive")
                refresh_profile()

        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label(action_label).classes("text-xl font-semibold")
            ui.label(
                "Scan this QR with the wallet you want to use for LNURL-auth "
                "on this account."
            ).classes(MUTED_TEXT)
            with ui.column().classes("items-center gap-3 w-full"):
                wallet_link.qrcode()
            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button(
                    "Close", icon="close", on_click=dialog.close
                ).classes(SECONDARY_BUTTON_CLASSES)
        dialog.open()

    def developer_request_dialog():
        with ui.dialog() as dialog, ui.card().classes(DIALOG_CLASSES):
            ui.label("Request developer access").classes(
                "text-xl font-semibold"
            )
            ui.label("Tell admins what you plan to register or test.").classes(
                MUTED_TEXT
            )
            reason = ui.textarea("Reason").classes(INPUT_CLASSES)

            async def submit():
                try:
                    permission_request = await create_permission_request(
                        session,
                        user.id,
                        permission_type=PermissionsEnum.DEVELOPER,
                        reason=reason.value,
                    )
                except PermissionRequestNotAllowed:
                    ui.notify(
                        "Your account already has developer access.",
                        type="warning",
                    )
                    refresh_profile()
                    return
                await session.commit()
                permission_request_events.emit(
                    {
                        "action": "created",
                        "permission_request_id": permission_request.id,
                        "permission_type": str(
                            permission_request.permission_type
                        ),
                        "requester_id": str(permission_request.requester_id),
                    }
                )
                ui.notify(
                    "Developer access request submitted.",
                    type="positive",
                )
                refresh_profile()

            with ui.row().classes("justify-end gap-3 w-full"):
                ui.button("Cancel", on_click=dialog.close).classes(
                    SECONDARY_BUTTON_CLASSES
                )
                ui.button("Submit", icon="send", on_click=submit).classes(
                    PRIMARY_BUTTON_CLASSES
                )
        dialog.open()

    with page_shell("max-w-5xl"):
        with card("gap-4"):
            with ui.row().classes(
                "w-full items-center justify-between gap-4 max-sm:flex-col "
                "max-sm:items-stretch"
            ):
                with ui.column().classes("gap-2"):
                    ui.label(user.nickname or "Unnamed User").classes(
                        "text-2xl font-semibold"
                    )
                    ui.label(user.email or "No email linked").classes(
                        MUTED_TEXT
                    )
                    with ui.row().classes("items-center gap-2 flex-wrap"):
                        if user.lnurl_pubkey:
                            ui.chip("Wallet linked", icon="link").props(
                                "outline"
                            ).classes(
                                "border-emerald-300 text-emerald-700 "
                                "dark:border-emerald-800 "
                                "dark:text-emerald-400"
                            )
                        else:
                            ui.chip("No wallet", icon="link_off").props(
                                "outline"
                            ).classes(
                                "border-red-300 text-red-700 "
                                "dark:border-red-800 dark:text-red-400"
                            )
                        for perm in user.permissions:
                            ui.chip(perm.permission_type, icon="check").props(
                                "outline"
                            ).classes(
                                "border-blue-300 text-blue-700 "
                                "dark:border-blue-800 dark:text-sky-300"
                            )
                ui.button(
                    "Logout",
                    icon="logout",
                    on_click=lambda: ui.navigate.to("/logout"),
                ).classes(SECONDARY_BUTTON_CLASSES)

        with responsive_grid(2, "gap-6"):
            with ui.column().classes("gap-6"):
                with card("gap-4"):
                    ui.label("Account Information").classes(
                        "text-xl font-semibold"
                    )
                    ui.separator()
                    _field_row(
                        "Nickname",
                        user.nickname or "Not set",
                        "Change nickname",
                        "edit",
                        nickname_dialog,
                    )
                    ui.separator()
                    _field_row(
                        "Email",
                        user.email or "No email linked",
                        "Change email",
                        "mail",
                        email_dialog,
                    )

                with card("gap-4"):
                    ui.label("Security").classes("text-xl font-semibold")
                    ui.separator()
                    ui.label(
                        "Manage your account credentials and access methods."
                    ).classes(MUTED_TEXT)
                    ui.button(
                        "Change password",
                        icon="lock",
                        on_click=password_dialog,
                    )

                with card("gap-4"):
                    ui.label("Wallet Connection").classes(
                        "text-xl font-semibold"
                    )
                    ui.separator()
                    with ui.column().classes("gap-2"):
                        ui.label("LNURL Pubkey").classes(
                            f"text-sm {MUTED_TEXT}"
                        )
                        ui.label(
                            user.lnurl_pubkey or "No wallet linked"
                        ).classes(TECH_TEXT)

                    with ui.row().classes("gap-3 flex-wrap"):
                        if user.lnurl_pubkey:
                            ui.button(
                                "Unlink wallet",
                                icon="link_off",
                                on_click=unlink_wallet_dialog,
                            ).classes(SECONDARY_BUTTON_CLASSES)
                            ui.button(
                                "Relink wallet",
                                icon="link",
                                on_click=wallet_link_dialog,
                            ).classes(SECONDARY_BUTTON_CLASSES)
                        else:
                            ui.button(
                                "Link wallet",
                                icon="bolt",
                                on_click=wallet_link_dialog,
                            ).classes(PRIMARY_BUTTON_CLASSES)

            with ui.column().classes("gap-6"):
                with card("gap-4"):
                    ui.label("Account Details").classes(
                        "text-xl font-semibold"
                    )
                    ui.separator()
                    with responsive_grid(2, "gap-4"):
                        _detail_row("Subject ID", str(user.id))
                        _detail_row("Login", user.login or "-")
                        _detail_row("Password", password_state)
                        _detail_row("Wallet", wallet_state)
                        _detail_row("Developer access", developer_state)
                        _detail_row("Created", created_at)

                with card("gap-4"):
                    ui.label("Developer Access").classes(
                        "text-xl font-semibold"
                    )
                    ui.separator()
                    if has_developer_access(permissions):
                        ui.label(
                            "Your account already has developer permissions."
                        ).classes(SUCCESS_TEXT)
                        ui.button(
                            "Go to Developer Dashboard",
                            icon="dashboard",
                            on_click=lambda: ui.navigate.to(
                                "/dashboard/developer"
                            ),
                        ).classes(PRIMARY_BUTTON_CLASSES)
                    if {
                        PermissionsEnum.ADMIN,
                        PermissionsEnum.ROOT,
                    } & permissions:
                        ui.label(
                            "Your account has admin permissions, which "
                            "include developer access."
                        ).classes(SUCCESS_TEXT)
                        ui.button(
                            "Go to Admin Dashboard",
                            icon="admin_panel_settings",
                            on_click=lambda: ui.navigate.to(
                                "/dashboard/admin"
                            ),
                        ).classes(PRIMARY_BUTTON_CLASSES)
                    if not has_developer_access(permissions):
                        ui.label(
                            "Request access to developer features, APIs and "
                            "application registration."
                        ).classes(MUTED_TEXT)
                        if latest_developer_request:
                            status = latest_developer_request.status
                            if status == PermissionRequestStatusEnum.PENDING:
                                ui.label(
                                    "Your developer access request is pending "
                                    "admin review."
                                ).classes(MUTED_TEXT)
                            elif status == PermissionRequestStatusEnum.DENIED:
                                ui.label(
                                    "Your last developer access request was "
                                    "denied. You can submit a new request "
                                    "with "
                                    "updated context."
                                ).classes(ERROR_TEXT)
                                ui.button(
                                    "Request again",
                                    icon="send",
                                    on_click=developer_request_dialog,
                                ).classes(SECONDARY_BUTTON_CLASSES)
                            else:
                                ui.label(
                                    f"Latest request status: {status}."
                                ).classes(MUTED_TEXT)
                        else:
                            ui.button(
                                "Request developer permissions",
                                icon="code",
                                on_click=developer_request_dialog,
                            ).classes(SECONDARY_BUTTON_CLASSES)
    footer()
