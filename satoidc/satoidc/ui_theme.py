from nicegui import app as nicegui_app
from nicegui import ui


def apply_theme() -> None:
    nicegui_app.config.quasar_config = {
        "brand": {
            "primary": "#3874C8",
            "secondary": "#F97316",
            "accent": "#38BDF8",
            "dark": "#070B16",
            "dark-page": "#070B16",
            "positive": "#16A34A",
            "negative": "#DC2626",
            "warning": "#F59E0B",
            "info": "#38BDF8",
        }
    }

    ui.button.default_props("flat no-caps")
    ui.button.default_classes(
        "rounded-xl px-4 py-2 font-medium transition-all duration-200 "
        "text-slate-800 dark:text-slate-100 hover:bg-slate-200/70 "
        "dark:hover:bg-slate-800"
    )
    field_classes = (
        "w-full rounded-xl bg-slate-100 dark:bg-slate-800 border "
        "border-slate-300 dark:border-slate-700 text-slate-900 "
        "dark:text-slate-100 placeholder:text-slate-400 "
        "dark:placeholder:text-slate-500 focus-within:ring-2 "
        "focus-within:ring-blue-500/40 transition-all duration-200"
    )
    ui.input.default_props("outlined dense color=info")
    ui.input.default_classes(field_classes)
    ui.textarea.default_props("outlined dense color=info")
    ui.textarea.default_classes(field_classes)
    ui.select.default_props("outlined dense color=info")
    ui.select.default_classes(field_classes)
    ui.card.default_classes(
        "rounded-2xl border border-slate-200 dark:border-slate-800 "
        "bg-white/80 dark:bg-slate-900/80 text-slate-900 "
        "dark:text-slate-100 backdrop-blur shadow-xl"
    )
    ui.table.default_classes(
        "overflow-hidden rounded-2xl border border-slate-200 "
        "dark:border-slate-800 bg-white/80 dark:bg-slate-900/80 "
        "text-slate-900 dark:text-slate-100 shadow-xl"
    )
