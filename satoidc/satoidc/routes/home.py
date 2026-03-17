from typing import Annotated

from fastapi import Depends
from nicegui import APIRouter, ui
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models.database import get_session

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


@ui.page("/", dark=True)
def index():
    ui.add_head_html(
        '<link href="https://unpkg.com/eva-icons@1.1.3/style/eva-icons.css"'
        ' rel="stylesheet" />'
    )
    with ui.header(fixed=False).classes(
        "bg-transparent border-b border-gray-700 items-center justify-between"
    ):
        # lado esquerdo
        with ui.row().classes("items-center gap-0"):
            ui.image("statics/imgs/logo.png").classes(
                "w-12 h-12 md:w-16 md:h-16"
            )
            ui.label("Sat").classes("text-2xl md:text-3xl font-bold")
            ui.label("OIDC").classes(
                "bg-gradient-to-r from-purple-500 via-indigo-500 to-blue-500 "
                "bg-clip-text text-transparent text-2xl md:text-3xl font-bold"
            )
        # menu desktop
        with ui.row().classes("max-md:hidden items-center gap-2"):
            with ui.link(
                target="https://github.com/Sats-Lottu/satoidc", new_tab=True
            ).classes("text-white"):
                ui.icon("eva-github").style("font-size:28px; padding:0")

            ui.button(
                "Login",
                on_click=lambda: ui.navigate.to("/login"),
            ).props("outline")

            ui.button(
                "Register",
                icon="arrow_right_alt",
                on_click=lambda: ui.navigate.to("/register"),
            ).props("outline")

        # menu mobile
        with ui.row().classes("flex md:hidden items-center"):
            menu_button = ui.button(icon="menu").props("flat round dense")

            with ui.menu().props("fit") as menu:
                ui.menu_item(
                    "GitHub",
                    lambda: ui.navigate.to(
                        "https://github.com/Sats-Lottu/satoidc", new_tab=True
                    ),
                )
                ui.menu_item("Login", lambda: ui.navigate.to("/login"))
                ui.menu_item("Register", lambda: ui.navigate.to("/register"))

            menu_button.on("click", menu.open)

    with (
        ui.row().classes("items-center justify-center h-full w-full"),
        ui.column().classes(
            "items-center justify-center gap-4 min-h-[50vh]  overflow-auto"
        ),
    ):
        ui.label("Welcome to SatOIDC").classes("text-4xl font-bold")
        ui.label("The OpenID Connect Provider for Bitcoiners").classes(
            "text-xl text-gray-400"
        )
        ui.button(
            "Get Started",
            icon="bolt",
            color="orange",
            on_click=lambda: ui.navigate.to("/register"),
        ).classes("""
                  px-10 py-4
                  text-lg font-bold text-white
                  rounded-xl
                  bg-gradient-to-r from-orange-400 to-orange-600
                  backdrop-blur
                  shadow-[0_0_30px_rgba(249,115,22,0.7)]
                  hover:shadow-[0_0_50px_rgba(249,115,22,1)]
                  hover:scale-105
                  transition-all duration-300""")

    with ui.footer().classes("bg-transparent justify-end"):
        ui.label("Made with ❤️ by Sats Lottu").classes("text-sm text-gray-500")
