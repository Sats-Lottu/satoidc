from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from nicegui import APIRouter, ui
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, with_loader_criteria

from satoidc.models import Permission, User
from satoidc.models.database import get_session
from satoidc.routes.ui_components import (
    MUTED_TEXT,
    PAGE,
    PRIMARY_BUTTON_CLASSES,
    SECONDARY_BUTTON_CLASSES,
    app_header,
    brand_mark,
    card,
    footer,
    responsive_grid,
)

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]

HOME_FEATURES = [
    (
        "verified_user",
        "OIDC Provider",
        "Standards-aligned discovery, JWKS, token and userinfo endpoints.",
    ),
    (
        "bolt",
        "LNURL-auth",
        "Password and wallet login paths with QR fallback for Lightning "
        "users.",
    ),
    (
        "app_registration",
        "Developer Console",
        "Client registration and OAuth2 settings in one focused operational "
        "interface.",
    ),
]


def _home_actions(is_signed_in: bool, can_develop: bool):  # pragma: no cover
    with ui.row().classes("gap-3 flex-wrap"):
        if is_signed_in:
            ui.button(
                "Open profile",
                icon="person",
                on_click=lambda: ui.navigate.to("/profile"),
            ).classes(f"{PRIMARY_BUTTON_CLASSES} text-base")
            if can_develop:
                ui.button(
                    "Developer Dashboard",
                    icon="dashboard",
                    on_click=lambda: ui.navigate.to("/dashboard/developer"),
                ).classes(f"{SECONDARY_BUTTON_CLASSES} px-6 py-3")
            ui.button(
                "Logout",
                icon="logout",
                on_click=lambda: ui.navigate.to("/logout"),
            ).classes(f"{SECONDARY_BUTTON_CLASSES} px-6 py-3")
            return

        ui.button(
            "Get Started",
            icon="bolt",
            on_click=lambda: ui.navigate.to("/register"),
        ).classes(f"{PRIMARY_BUTTON_CLASSES} text-base")
        ui.button(
            "Sign in",
            icon="login",
            on_click=lambda: ui.navigate.to("/login"),
        ).classes(f"{SECONDARY_BUTTON_CLASSES} px-6 py-3")


def _home_feature_cards():  # pragma: no cover
    with responsive_grid(3, "gap-4"):
        for icon, title, body in HOME_FEATURES:
            with card(
                "gap-3 p-5 hover:-translate-y-0.5 "
                "hover:bg-white/90 dark:hover:bg-slate-900"
            ):
                ui.icon(icon).classes(
                    "text-sky-700 dark:text-sky-300 text-3xl"
                )
                ui.label(title).classes(
                    "text-lg font-semibold tracking-tight"
                )
                ui.label(body).classes(f"text-sm leading-6 {MUTED_TEXT}")


@ui.page("/")
async def index(session: Session, request: Request):  # pragma: no cover
    user = None
    permissions: set[str] = set()
    user_id = request.session.get("user_id")
    if user_id:
        try:
            user_uuid = UUID(user_id)
        except (TypeError, ValueError):
            user_uuid = None
        if user_uuid:
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
                .where(User.id == user_uuid)
            )
            if user:
                permissions = {
                    str(permission.permission_type)
                    for permission in user.permissions
                }

    is_signed_in = user is not None
    can_develop = bool({"developer", "admin", "root"} & permissions)
    can_admin = bool({"admin", "root"} & permissions)

    nav_items = [("GitHub", "https://github.com/Sats-Lottu/satoidc", "github")]
    account_items = [("Profile", "/profile", "person")]
    if can_develop:
        account_items.append(
            ("Developer Dashboard", "/dashboard/developer", "dashboard")
        )
    if can_admin:
        account_items.append(
            ("Admin Dashboard", "/dashboard/admin", "admin_panel_settings")
        )
    account_items.append(("Logout", "/logout", "logout"))

    if not is_signed_in:
        nav_items.extend(
            [
                ("Login", "/login", "login"),
                ("Register", "/register", "person_add"),
            ]
        )

    app_header(
        nav=nav_items,
        user_label=(
            (user.nickname or user.login or "Account") if user else None
        ),
        account_items=account_items if is_signed_in else None,
    )
    with ui.column().classes(PAGE):
        with ui.column().classes(
            "w-full max-w-5xl mx-auto px-4 py-12 md:py-20 gap-8"
        ):
            with ui.column().classes("max-w-3xl gap-5"):
                with ui.row().classes(
                    "items-center gap-3 rounded-full border "
                    "border-slate-200/70 bg-white/65 px-3 py-2 "
                    "shadow-sm shadow-slate-200/50 backdrop-blur-xl "
                    "dark:border-white/10 dark:bg-slate-900/60 "
                    "dark:shadow-none"
                ):
                    brand_mark(size_classes="h-8 w-8")
                    ui.label("SatOIDC Identity Provider").classes(
                        "text-sm font-semibold text-sky-700 "
                        "dark:text-sky-300"
                    )
                ui.label("OpenID Connect for Bitcoin-native identity").classes(
                    "text-4xl font-bold leading-tight tracking-tight "
                    "text-slate-950 dark:text-white md:text-5xl"
                )
                ui.label(
                    "SatOIDC combines standard OAuth2/OIDC flows with "
                    "Lightning LNURL-auth for secure account access, "
                    "client registration, and developer-ready identity "
                    "workflows."
                ).classes(f"text-lg leading-8 {MUTED_TEXT}")
                _home_actions(is_signed_in, can_develop)

            _home_feature_cards()
    footer()
