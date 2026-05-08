from nicegui import APIRouter, ui

from satoidc.routes.ui_components import (
    ERROR_TEXT,
    MUTED_TEXT,
    PRIMARY_BUTTON_CLASSES,
    card,
    page_shell,
)

router = APIRouter()


@router.page("/forbidden")
async def forbidden_get():  # pragma: no cover
    with page_shell("max-w-lg"):
        with card("items-center gap-3 text-center"):
            ui.icon("block").classes(f"{ERROR_TEXT} text-5xl")
            ui.label("Forbidden").classes("text-2xl font-bold")
            ui.label("You don't have permission to access this page.").classes(
                MUTED_TEXT
            )
            ui.button(
                "Go to home",
                icon="home",
                on_click=lambda: ui.navigate.to("/"),
            ).classes(f"mt-2 {PRIMARY_BUTTON_CLASSES}")
