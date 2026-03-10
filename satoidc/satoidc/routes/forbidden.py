from nicegui import APIRouter, ui

router = APIRouter()


@router.page("/forbidden")
async def forbidden_get():
    with ui.column().classes("self-center items-center h-full w-full"):
        ui.label("Forbidden").classes("text-2xl font-bold text-red-500")
        ui.label("You don't have permission to access this page.").classes(
            "text-red-500"
        )
        ui.button("Go to home", on_click=lambda: ui.navigate.to("/")).classes(
            "mt-4"
        )
