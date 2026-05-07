# ruff: noqa: PLR1702

from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, with_loader_criteria

from satoidc.models import Permission, User
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    SUCCESS_TEXT,
    TECH_TEXT,
    card,
    footer,
    page_shell,
)

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


def _field_row(label: str, value: str, action_label: str, icon: str):
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
            on_click=lambda: ui.notify(
                f"{action_label} is not available yet."
            ),
        ).classes(SECONDARY_BUTTON_CLASSES)


@ui.page("/profile")
async def profile(session: Session, request: Request):  # noqa: PLR0915, PLR1702
    user_id = request.session.get("user_id")
    user = await session.scalar(
        select(User)
        .options(
            joinedload(User.permissions),
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

        with ui.grid(columns=2).classes(
            "w-full gap-6 max-md:grid-cols-1"
        ):
            with ui.column().classes("gap-6"):
                with card("gap-4"):
                    ui.label("User Info").classes("text-xl font-semibold")
                    ui.separator()
                    _field_row(
                        "Nickname",
                        user.nickname or "Not set",
                        "Change nickname",
                        "edit",
                    )
                    ui.separator()
                    _field_row(
                        "Email",
                        user.email or "No email linked",
                        "Change email",
                        "mail",
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
                        on_click=lambda: ui.notify(
                            "Change password is not available yet."
                        ),
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
                                on_click=lambda: ui.notify(
                                    "Wallet unlink is not available yet."
                                ),
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
                        ui.button(
                            label,
                            icon=icon,
                            on_click=lambda label=label: ui.notify(
                                f"{label} is not available yet."
                            ),
                        ).classes(f"w-full {SECONDARY_BUTTON_CLASSES}")
                    wallet_label = (
                        "Unlink wallet" if user.lnurl_pubkey else "Link wallet"
                    )
                    wallet_icon = "link_off" if user.lnurl_pubkey else "link"
                    ui.button(
                        wallet_label,
                        icon=wallet_icon,
                        on_click=lambda: ui.notify(
                            f"{wallet_label} is not available yet."
                        ),
                    ).classes(f"w-full {SECONDARY_BUTTON_CLASSES}")
    footer()
