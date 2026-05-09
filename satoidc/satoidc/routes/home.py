from typing import Annotated

from fastapi import Depends
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession

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


@ui.page("/")
def index():  # pragma: no cover
    app_header(
        nav=[
            ("GitHub", "https://github.com/Sats-Lottu/satoidc", "github"),
            ("Login", "/login", "login"),
            ("Register", "/register", "person_add"),
        ]
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
                with ui.row().classes("gap-3 flex-wrap"):
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

            with responsive_grid(3, "gap-4"):
                for icon, title, body in [
                    (
                        "verified_user",
                        "OIDC Provider",
                        "Standards-aligned discovery, JWKS, token and "
                        "userinfo endpoints.",
                    ),
                    (
                        "bolt",
                        "LNURL-auth",
                        "Password and wallet login paths with QR fallback "
                        "for Lightning users.",
                    ),
                    (
                        "app_registration",
                        "Developer Console",
                        "Client registration and OAuth2 settings in one "
                        "focused operational interface.",
                    ),
                ]:
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
                        ui.label(body).classes(
                            f"text-sm leading-6 {MUTED_TEXT}"
                        )
    footer()
