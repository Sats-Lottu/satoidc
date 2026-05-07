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
    card,
    footer,
)

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


@ui.page("/")
def index():
    app_header(
        nav=[
            ("GitHub", "https://github.com/Sats-Lottu/satoidc", "github"),
            ("Login", "/login", "login"),
            ("Register", "/register", "person_add"),
        ]
    )
    with ui.column().classes(PAGE):
        with ui.column().classes(
            "w-full max-w-5xl mx-auto px-4 py-14 md:py-20 gap-8"
        ):
            with ui.column().classes("max-w-3xl gap-5"):
                ui.label("Welcome to SatOIDC").classes(
                    "text-sm font-semibold text-blue-700 dark:text-sky-300"
                )
                ui.label("OpenID Connect for Bitcoin-native identity").classes(
                    "text-4xl font-bold leading-tight text-slate-950 "
                    "dark:text-white md:text-5xl"
                )
                ui.label(
                    "SatOIDC combines standard OAuth2/OIDC flows with "
                    "Lightning LNURL-auth for secure account access, client "
                    "registration, and developer-ready identity workflows."
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

            with ui.grid(columns=3).classes(
                "w-full gap-4 max-md:grid-cols-1"
            ):
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
                        "gap-3 p-5 hover:bg-slate-100 "
                        "dark:hover:bg-slate-800"
                    ):
                        ui.icon(icon).classes(
                            "text-blue-700 dark:text-sky-300 text-3xl"
                        )
                        ui.label(title).classes("text-lg font-semibold")
                        ui.label(body).classes(
                            f"text-sm leading-6 {MUTED_TEXT}"
                        )
    footer()
