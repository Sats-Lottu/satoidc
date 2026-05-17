from collections.abc import Callable, Iterable

from nicegui import context, ui

PAGE = (
    "min-h-screen w-full bg-gradient-to-br from-sky-50/90 via-[#F6F8FC] "
    "to-indigo-50/70 text-slate-950 dark:from-slate-950 "
    "dark:via-slate-950 dark:to-slate-900 dark:text-slate-50 "
    "selection:bg-sky-400/30"
)
CONTENT = "w-full max-w-5xl mx-auto px-4 py-8 md:px-6 md:py-10"
AUTH_CONTENT = "w-full mx-auto px-4 py-8 sm:py-10"
PANEL = (
    "w-full rounded-2xl border border-slate-200/70 bg-white/75 "
    "text-slate-950 shadow-xl shadow-slate-200/60 backdrop-blur-xl "
    "dark:border-white/10 dark:bg-slate-900/80 dark:text-slate-50 "
    "dark:shadow-2xl dark:shadow-black/20"
)
PANEL_PADDED = f"{PANEL} p-5"
MUTED_TEXT = "text-slate-600 dark:text-slate-400"
ERROR_TEXT = "text-red-600 dark:text-red-400"
SUCCESS_TEXT = "text-emerald-700 dark:text-emerald-400"
LINK_CLASSES = (
    "text-sky-700 dark:text-sky-300 hover:text-sky-600 "
    "dark:hover:text-sky-200 transition-colors duration-200"
)
ICON_BUTTON_CLASSES = (
    "text-slate-700 dark:text-slate-200 hover:bg-white/90 "
    "dark:hover:bg-slate-800/90 border border-slate-200/70 "
    "dark:border-white/10 bg-white/65 dark:bg-slate-900/60 "
    "shadow-sm shadow-slate-200/40 dark:shadow-none"
)
PRIMARY_BUTTON_CLASSES = (
    "rounded-lg px-6 py-3 font-semibold !bg-gradient-to-r "
    "!from-amber-500 !to-orange-500 hover:!from-amber-400 "
    "hover:!to-orange-400 !text-slate-950 shadow-lg "
    "shadow-amber-500/20 dark:shadow-orange-950/30 transition-all "
    "duration-200"
)
SECONDARY_BUTTON_CLASSES = (
    "rounded-lg border border-slate-200/80 dark:border-white/10 "
    "!bg-white/70 dark:!bg-slate-900/65 hover:!bg-white/95 "
    "dark:hover:!bg-slate-800/90 !text-slate-800 dark:!text-slate-100 "
    "shadow-sm shadow-slate-200/40 dark:shadow-none transition-all "
    "duration-200"
)
INPUT_CLASSES = (
    "w-full rounded-lg text-slate-950 dark:text-slate-50 "
    "placeholder:text-slate-500 dark:placeholder:text-slate-500 "
    "transition-colors duration-200"
)
DIALOG_CLASSES = (
    "w-[calc(100vw-2rem)] max-w-2xl max-h-[90vh] overflow-y-auto "
    "rounded-2xl border border-slate-200/70 dark:border-white/10 "
    "bg-white/90 dark:bg-slate-900/95 text-slate-950 dark:text-slate-50 "
    "p-5 sm:p-6 shadow-2xl shadow-slate-300/60 "
    "dark:shadow-black/30 backdrop-blur-xl"
)
TECH_TEXT = "text-sm break-all text-slate-900 dark:text-slate-100"

GRID_COLUMNS = {
    2: "md:grid-cols-2",
    3: "md:grid-cols-3",
}

LOGO_ASSETS = {
    "dark": "statics/imgs/logo.png",
    "light": "statics/imgs/logo.png",
    "icon": "statics/imgs/logo.png",
    "mono": "statics/imgs/logo.png",
}

GITHUB_MARK_SVG = """
<svg
  aria-hidden="true"
  viewBox="0 0 24 24"
  width="20"
  height="20"
  fill="currentColor"
>
  <path d="
    M12 .297c-6.63 0-12 5.373-12 12
    0 5.303 3.438 9.8 8.205 11.385
    .6.113.82-.258.82-.577
    0-.285-.01-1.04-.015-2.04
    -3.338.724-4.042-1.61-4.042-1.61
    -.546-1.387-1.333-1.756-1.333-1.756
    -1.087-.744.084-.729.084-.729
    1.205.084 1.838 1.236 1.838 1.236
    1.07 1.835 2.809 1.305 3.495.998
    .108-.776.418-1.305.762-1.605
    -2.665-.3-5.466-1.332-5.466-5.93
    0-1.31.465-2.38 1.235-3.22
    -.135-.303-.54-1.523.105-3.176
    0 0 1.005-.322 3.3 1.23
    .96-.267 1.98-.399 3-.405
    1.02.006 2.04.138 3 .405
    2.28-1.552 3.285-1.23 3.285-1.23
    .645 1.653.24 2.873.12 3.176
    .765.84 1.23 1.91 1.23 3.22
    0 4.61-2.805 5.625-5.475 5.92
    .42.36.81 1.096.81 2.22
    0 1.606-.015 2.896-.015 3.286
    0 .315.21.69.825.57
    C20.565 22.092 24 17.592 24 12.297
    c0-6.627-5.373-12-12-12
  "/>
</svg>
"""


def brand_mark(
    *,
    variant: str = "icon",
    size_classes: str = "h-9 w-9",
):  # pragma: no cover
    asset = LOGO_ASSETS.get(variant, LOGO_ASSETS["icon"])
    with ui.element("div").classes(
        "flex items-center justify-center rounded-xl border "
        "border-slate-200/70 bg-white/80 p-1 shadow-sm "
        "shadow-slate-200/60 dark:border-white/10 dark:bg-white/5 "
        "dark:shadow-none"
    ):
        return ui.image(asset).classes(
            f"{size_classes} object-contain saturate-125 contrast-110 "
            "drop-shadow-sm dark:saturate-100 dark:contrast-100"
        )


def _brand(on_click: Callable[[], None] | None = None):  # pragma: no cover
    row = ui.row().classes(
        "items-center gap-2 cursor-pointer rounded-xl px-2 py-1 "
        "transition-colors duration-200 hover:bg-white/70 "
        "dark:hover:bg-slate-900/70"
    )
    if on_click:
        row.on("click", on_click)
    with row:
        brand_mark(variant="icon")
        with ui.row().classes("items-baseline gap-0"):
            ui.label("Sat").classes(
                "text-xl font-bold tracking-tight text-slate-950 "
                "dark:text-white"
            )
            ui.label("OIDC").classes(
                "text-xl font-bold tracking-tight text-sky-600 "
                "dark:text-sky-300"
            )
    return row


def _github_link(target: str):  # pragma: no cover
    with ui.link(target=target, new_tab=True).classes(
        "inline-flex h-10 w-10 items-center justify-center rounded-full "
        f"{ICON_BUTTON_CLASSES} hover:shadow-sm"
    ).props('aria-label="SatOIDC GitHub repository"'):
        ui.html(GITHUB_MARK_SVG).classes(
            "flex h-5 w-5 items-center justify-center "
            "text-slate-900 dark:text-white"
        )


def _github_menu_item(label: str, target: str):  # pragma: no cover
    item = ui.item(
        on_click=lambda: ui.navigate.to(target, new_tab=True)
    ).classes("items-center gap-2 cursor-pointer")
    with item:
        with ui.item_section().props("avatar"):
            ui.html(GITHUB_MARK_SVG).classes(
                "flex h-5 w-5 items-center justify-center "
                "text-slate-900 dark:text-white"
            )
        with ui.item_section():
            ui.item_label(label)


def _nav_button(label: str, target: str, icon: str):  # pragma: no cover
    if icon == "github":
        _github_link(target)
        return
    ui.button(
        label,
        icon=icon,
        on_click=lambda: ui.navigate.to(target),
    ).classes(SECONDARY_BUTTON_CLASSES)


def _desktop_nav(nav_items: list[tuple[str, str, str]]):  # pragma: no cover
    with ui.row().classes("max-md:hidden items-center gap-2"):
        for label, target, icon in nav_items:
            _nav_button(label, target, icon)


def _mobile_nav(nav_items: list[tuple[str, str, str]]):  # pragma: no cover
    with ui.row().classes("flex md:hidden items-center"):
        menu_button = ui.button(icon="menu").props(
            'flat round dense aria-label="Open navigation menu"'
        ).classes(ICON_BUTTON_CLASSES)
        with ui.menu().props("fit") as menu:
            for label, target, icon in nav_items:
                if icon == "github":
                    _github_menu_item(label, target)
                else:
                    ui.menu_item(
                        label,
                        lambda target=target: ui.navigate.to(target),
                    )
        menu_button.on("click", menu.open)


def _account_menu(
    user_label: str,
    account_items: list[tuple[str, str, str]],
):  # pragma: no cover
    with ui.dropdown_button(
        user_label, icon="account_circle", auto_close=True
    ).props("flat").classes(SECONDARY_BUTTON_CLASSES):
        for label, target, icon in account_items:
            item = ui.item(
                on_click=lambda target=target: ui.navigate.to(target)
            ).classes("items-center gap-2 cursor-pointer")
            with item:
                with ui.item_section().props("avatar"):
                    ui.icon(icon)
                with ui.item_section():
                    ui.item_label(label)


def _theme_toggle():  # pragma: no cover
    dark_mode = ui.dark_mode(value=False)

    with ui.row().classes(
        "items-center gap-1 rounded-full border border-slate-200/70 "
        "bg-white/70 px-2 py-1 text-slate-700 shadow-sm "
        "shadow-slate-200/40 transition-all duration-200 "
        "dark:border-white/10 dark:bg-slate-900/70 dark:text-slate-100 "
        "dark:shadow-none"
    ):
        ui.icon("wb_sunny").classes("text-lg").bind_name_from(
            dark_mode,
            "value",
            backward=lambda value: "dark_mode" if value else "wb_sunny",
        )
        ui.switch().props(
            'dense color="info" aria-label="Switch color theme"'
        ).bind_value(dark_mode)


def _configure_page_content():  # pragma: no cover
    context.client.content.classes("p-0 gap-0")


def app_header(  # noqa: PLR1702
    *,
    title: str | None = None,
    user_label: str | None = None,
    nav: Iterable[tuple[str, str, str]] = (),
    account_items: Iterable[tuple[str, str, str]] | None = None,
    show_brand: bool = True,
):  # pragma: no cover
    _configure_page_content()
    with ui.header(fixed=False).classes(
        "bg-white/70 dark:bg-slate-950/75 text-slate-950 dark:text-white "
        "border-b border-slate-200/70 dark:border-white/10 items-center "
        "justify-between px-4 py-2 backdrop-blur-xl"
    ):
        if show_brand:
            _brand(lambda: ui.navigate.to("/"))
        elif title:
            ui.label(title).classes("text-xl font-bold")

        nav_items = list(nav)
        account_menu_items = list(
            account_items
            or [
                ("Profile", "/profile", "person"),
                ("Logout", "/logout", "logout"),
            ]
        )
        with ui.row().classes("items-center gap-2"):
            if nav_items:
                _desktop_nav(nav_items)
                _mobile_nav(nav_items)
            _theme_toggle()
            if user_label:
                _account_menu(user_label, account_menu_items)


def page_shell(max_width: str = "max-w-5xl"):  # pragma: no cover
    app_header()
    with ui.column().classes(PAGE):
        return ui.column().classes(
            f"w-full {max_width} mx-auto px-4 py-6 md:px-6 md:py-8 gap-6"
        )


def auth_shell(max_width: str = "max-w-5xl"):  # pragma: no cover
    app_header()
    with ui.column().classes(PAGE):
        return ui.column().classes(f"{AUTH_CONTENT} {max_width} gap-4")


def card(classes: str = ""):  # pragma: no cover
    return ui.card().classes(
        f"{PANEL_PADDED} transition-all duration-200 {classes}".strip()
    )


def responsive_grid(columns: int = 2, classes: str = ""):  # pragma: no cover
    desktop_columns = GRID_COLUMNS.get(columns, GRID_COLUMNS[2])
    return ui.element("div").classes(
        f"grid w-full grid-cols-1 {desktop_columns} {classes}".strip()
    )


def section_title(title: str, subtitle: str | None = None):  # pragma: no cover
    with ui.column().classes("gap-1"):
        ui.label(title).classes("text-2xl font-semibold tracking-tight")
        if subtitle:
            ui.label(subtitle).classes(MUTED_TEXT)


def auth_context_panel(
    *,
    eyebrow: str,
    title: str,
    body: str,
    features: Iterable[tuple[str, str, str]],
):  # pragma: no cover
    with ui.column().classes(
        "hidden md:flex flex-col h-full justify-between gap-8 rounded-2xl "
        "border border-slate-200/70 bg-white/60 p-6 shadow-xl "
        "shadow-slate-200/40 backdrop-blur-xl dark:border-white/10 "
        "dark:bg-slate-900/55 dark:shadow-black/10"
    ):
        with ui.column().classes("gap-4"):
            ui.label(eyebrow).classes(
                "text-sm font-semibold text-sky-700 dark:text-sky-300"
            )
            ui.label(title).classes(
                "text-3xl font-semibold leading-tight tracking-tight"
            )
            ui.label(body).classes(f"text-base leading-7 {MUTED_TEXT}")
        with ui.column().classes("gap-3"):
            for icon, feature_title, feature_body in features:
                with ui.row().classes(
                    "gap-3 rounded-xl border border-slate-200/70 "
                    "bg-white/70 p-3 shadow-sm shadow-slate-200/30 "
                    "dark:border-white/10 dark:bg-slate-950/35 "
                    "dark:shadow-none"
                ):
                    ui.icon(icon).classes(
                        "text-sky-600 dark:text-sky-300 text-2xl"
                    )
                    with ui.column().classes("gap-1"):
                        ui.label(feature_title).classes("font-semibold")
                        ui.label(feature_body).classes(
                            f"text-sm leading-6 {MUTED_TEXT}"
                        )


def empty_state(  # noqa: PLR0913
    *,
    icon: str,
    title: str,
    body: str,
    action_label: str | None = None,
    action_icon: str | None = None,
    on_action: Callable[[], None] | None = None,
):  # pragma: no cover
    with card("items-center gap-3 text-center"):
        ui.icon(icon).classes("text-sky-300 text-5xl")
        ui.label(title).classes("text-xl font-semibold")
        ui.label(body).classes(MUTED_TEXT)
        if action_label and on_action:
            ui.button(action_label, icon=action_icon, on_click=on_action)


def footer():  # pragma: no cover
    with ui.footer(fixed=False).classes(
        "bg-transparent text-slate-500 dark:text-slate-500 justify-end "
        "px-4 py-2"
    ):
        ui.label("Made with love by Sats Lottu").classes("text-sm")
