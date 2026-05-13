# ruff: noqa: PLR1702

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, with_loader_criteria

from satoidc.auth.security import hash_password, verify_password
from satoidc.models import Permission, User
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
):
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


@ui.page("/profile")
async def profile(session: Session, request: Request):  # noqa: PLR0915, PLR1702  # pragma: no cover
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
            email = ui.input("Email", value=user.email or "").props(
                "type=email"
            ).classes(INPUT_CLASSES)

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
                    ui.label("User Info").classes("text-xl font-semibold")
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
                    ui.label("Developer Access").classes(
                        "text-xl font-semibold"
                    )
                    ui.separator()
                    if {"developer", "admin", "root"} & permissions:
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
                    if {"admin", "root"} & permissions:
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
                    if not permissions:
                        ui.label(
                            "Request access to developer features, APIs and "
                            "application registration."
                        ).classes(MUTED_TEXT)
                        ui.button(
                            "Request developer permissions",
                            icon="code",
                            on_click=lambda: ui.notify(
                                "Developer permission request sent for review."
                            ),
                        ).classes(SECONDARY_BUTTON_CLASSES)

            with ui.column().classes("gap-6"):
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
                                on_click=lambda: ui.notify(
                                    "Wallet relink is not available yet."
                                ),
                            ).classes(SECONDARY_BUTTON_CLASSES)
                        else:
                            ui.button(
                                "Link wallet",
                                icon="bolt",
                                on_click=lambda: ui.notify(
                                    "Wallet link is not available yet."
                                ),
                            ).classes(PRIMARY_BUTTON_CLASSES)

                with card("gap-4"):
                    ui.label("Quick Actions").classes("text-xl font-semibold")
                    ui.separator()
                    for label, icon in [
                        ("Edit nickname", "person"),
                        ("Edit email", "alternate_email"),
                        ("Change password", "password"),
                    ]:
                        actions = {
                            "Edit nickname": nickname_dialog,
                            "Edit email": email_dialog,
                            "Change password": password_dialog,
                        }
                        ui.button(
                            label,
                            icon=icon,
                            on_click=actions[label],
                        ).classes(f"w-full {SECONDARY_BUTTON_CLASSES}")
                    wallet_label = (
                        "Unlink wallet" if user.lnurl_pubkey else "Link wallet"
                    )
                    wallet_icon = "link_off" if user.lnurl_pubkey else "link"
                    ui.button(
                        wallet_label,
                        icon=wallet_icon,
                        on_click=(
                            unlink_wallet_dialog
                            if user.lnurl_pubkey
                            else lambda: ui.notify(
                                "Wallet link is not available yet."
                            )
                        ),
                    ).classes(f"w-full {SECONDARY_BUTTON_CLASSES}")
    footer()
